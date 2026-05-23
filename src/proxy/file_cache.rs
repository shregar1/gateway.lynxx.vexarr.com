//! High-performance file serving primitives: mmap, FD cache, metadata cache,
//! page-cache hints, sendfile infrastructure, and configurable strategies.
//!
//! # Architecture
//!
//! ```text
//! FileCache (configurable strategy: Read / Mmap / Sendfile)
//! ├── MappedFile          — Safe mmap wrapper (unix only)
//! │   └── MmapSlice       — Zero-copy Bytes via bytes::from_owner
//! ├── CachedEntry         — FD + mmap + metadata per file
//! │   └── CachedMetadata  — ETag, Last-Modified, content-type, size
//! ├── PageCacheAdvisor    — posix_fadvise hints (Linux)
//! ├── sendfile wrapper    — Zero-copy socket transfer (Linux)
//! └── FileCacheMetrics    — Hit/miss/eviction counters
//! ```
//!
//! # Why
//!
//! Without caching, every static file request does: `open()` → `fstat()`
//! → `read()` → `close()` — four syscalls plus a full-file heap allocation.
//! With the file cache:
//!
//! - **FD cache**: eliminates `open()`/`close()` for hot files.
//! - **Metadata cache**: eliminates `fstat()` — ETag/Last-Modified served
//!   from memory.
//! - **mmap**: eliminates `read()` heap allocation — data served directly
//!   from the kernel page cache via zero-copy `Bytes`.
//! - **Page-cache hints**: `posix_fadvise(SEQUENTIAL)` triggers kernel
//!   read-ahead for sequential file access patterns.
//! - **sendfile**: (Linux + kTLS) bypasses userspace entirely — kernel
//!   transfers file data directly to the encrypted socket.

use bytes::Bytes;
use dashmap::DashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

type FastHasher = ahash::RandomState;

// ---------------------------------------------------------------------------
// File serve strategy
// ---------------------------------------------------------------------------

/// How file content is served. Stored as `AtomicU8` for lock-free switching.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileServeStrategy {
    /// Standard `tokio::fs::read()` — current behaviour. Simple, safe,
    /// allocates a `Vec<u8>` per request.
    Read = 0,
    /// Memory-mapped I/O — zero-copy `Bytes` from the kernel page cache.
    /// Best for medium-to-large files with repeated access. Default.
    Mmap = 1,
    /// Linux `sendfile(2)` for zero-copy socket transfer. Requires kTLS
    /// for TLS connections. Falls back to Mmap when kTLS is unavailable.
    Sendfile = 2,
}

impl FileServeStrategy {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Mmap,
            2 => Self::Sendfile,
            _ => Self::Read,
        }
    }
}

static FILE_SERVE_STRATEGY: AtomicU8 = AtomicU8::new(FileServeStrategy::Mmap as u8);
static FILE_CACHE_ENABLED: AtomicBool = AtomicBool::new(true);
/// Directory listing disabled by default (security).
static DIRECTORY_LISTING_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn set_file_serve_strategy(s: FileServeStrategy) {
    FILE_SERVE_STRATEGY.store(s as u8, Ordering::Relaxed);
}

pub fn file_serve_strategy() -> FileServeStrategy {
    FileServeStrategy::from_u8(FILE_SERVE_STRATEGY.load(Ordering::Relaxed))
}

pub fn set_file_cache_enabled(enabled: bool) {
    FILE_CACHE_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_file_cache_enabled() -> bool {
    FILE_CACHE_ENABLED.load(Ordering::Relaxed)
}

pub fn set_directory_listing_enabled(enabled: bool) {
    DIRECTORY_LISTING_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_directory_listing_enabled() -> bool {
    DIRECTORY_LISTING_ENABLED.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// MappedFile — Safe mmap wrapper (Unix)
// ---------------------------------------------------------------------------

/// Memory-mapped file for zero-copy reads from the kernel page cache.
/// The mapping is read-only (`PROT_READ`) and private (`MAP_PRIVATE`),
/// so it's safe to share across threads.
///
/// On drop, the mapping is unmapped via `munmap()` and the underlying
/// file descriptor is closed.
#[cfg(unix)]
pub struct MappedFile {
    ptr: *mut u8,
    len: usize,
    /// Keep the file open while the mapping exists — the kernel requires
    /// the FD to remain valid for the lifetime of the mapping.
    _file: std::fs::File,
}

#[cfg(unix)]
impl MappedFile {
    /// Create a read-only memory mapping of the given file.
    pub fn new(file: std::fs::File) -> std::io::Result<Self> {
        use std::os::unix::io::AsRawFd;

        let len = file.metadata()?.len() as usize;
        if len == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "cannot mmap empty file",
            ));
        }

        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self {
            ptr: ptr as *mut u8,
            len,
            _file: file,
        })
    }

    /// Full file contents as a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// A sub-range of the file. Clamps to file bounds.
    pub fn range(&self, offset: usize, len: usize) -> &[u8] {
        let end = (offset + len).min(self.len);
        let start = offset.min(end);
        &self.as_slice()[start..end]
    }

    /// File size in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(unix)]
impl Drop for MappedFile {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
    }
}

// Safety: MappedFile is PROT_READ + MAP_PRIVATE — immutable, no shared
// mutations. Multiple threads can safely read from the same mapping.
#[cfg(unix)]
unsafe impl Send for MappedFile {}
#[cfg(unix)]
unsafe impl Sync for MappedFile {}

// ---------------------------------------------------------------------------
// MmapSlice — Zero-copy Bytes from mmap via bytes::from_owner
// ---------------------------------------------------------------------------

/// A reference-counted slice into a `MappedFile`. Implements `AsRef<[u8]>`
/// so it can be wrapped in `bytes::Bytes::from_owner()` for true zero-copy
/// body responses — no `memcpy` between page cache and userspace.
#[cfg(unix)]
struct MmapSlice {
    mmap: Arc<MappedFile>,
    offset: usize,
    len: usize,
}

#[cfg(unix)]
impl AsRef<[u8]> for MmapSlice {
    fn as_ref(&self) -> &[u8] {
        self.mmap.range(self.offset, self.len)
    }
}

/// Create a zero-copy `Bytes` backed by a memory-mapped file region.
/// The `Arc<MappedFile>` keeps the mapping alive as long as the `Bytes`
/// (and any slices derived from it) exist.
#[cfg(unix)]
pub fn mmap_to_bytes(mmap: &Arc<MappedFile>, offset: usize, len: usize) -> Bytes {
    Bytes::from_owner(MmapSlice {
        mmap: Arc::clone(mmap),
        offset,
        len,
    })
}

// ---------------------------------------------------------------------------
// Page cache advisor (Linux)
// ---------------------------------------------------------------------------

/// Hint to the kernel that this file will be read sequentially.
/// Triggers aggressive read-ahead, improving throughput for large files.
#[cfg(target_os = "linux")]
pub fn advise_sequential(file: &std::fs::File) {
    use std::os::unix::io::AsRawFd;
    unsafe {
        libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
    }
}

/// Hint that a specific range will be needed soon — prefetch into page cache.
#[cfg(target_os = "linux")]
pub fn advise_willneed(file: &std::fs::File, offset: i64, len: i64) {
    use std::os::unix::io::AsRawFd;
    unsafe {
        libc::posix_fadvise(file.as_raw_fd(), offset, len, libc::POSIX_FADV_WILLNEED);
    }
}

/// Hint that this file data won't be needed again — allow eviction.
#[cfg(target_os = "linux")]
pub fn advise_dontneed(file: &std::fs::File, offset: i64, len: i64) {
    use std::os::unix::io::AsRawFd;
    unsafe {
        libc::posix_fadvise(file.as_raw_fd(), offset, len, libc::POSIX_FADV_DONTNEED);
    }
}

// macOS: no posix_fadvise — the unified buffer cache handles this automatically.
#[cfg(not(target_os = "linux"))]
pub fn advise_sequential(_file: &std::fs::File) {}
#[cfg(not(target_os = "linux"))]
pub fn advise_willneed(_file: &std::fs::File, _offset: i64, _len: i64) {}
#[cfg(not(target_os = "linux"))]
pub fn advise_dontneed(_file: &std::fs::File, _offset: i64, _len: i64) {}

// ---------------------------------------------------------------------------
// sendfile wrapper (Linux)
// ---------------------------------------------------------------------------

/// Zero-copy file-to-socket transfer via `sendfile(2)`. Returns the number
/// of bytes transferred.
///
/// **Requirements**: the output FD must be a socket (not a regular file).
/// For TLS connections, kTLS must be enabled so the kernel handles
/// encryption — otherwise sendfile bypasses the TLS layer and sends
/// plaintext.
///
/// Typically called from a custom `Body` implementation or a dedicated
/// static-file code path that has access to the raw socket FD.
#[cfg(target_os = "linux")]
pub fn sendfile_transfer(
    out_fd: std::os::unix::io::RawFd,
    in_fd: std::os::unix::io::RawFd,
    offset: &mut i64,
    count: usize,
) -> std::io::Result<usize> {
    let n = unsafe { libc::sendfile(out_fd, in_fd, offset, count) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

#[cfg(not(target_os = "linux"))]
pub fn sendfile_transfer(
    _out_fd: i32,
    _in_fd: i32,
    _offset: &mut i64,
    _count: usize,
) -> std::io::Result<usize> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "sendfile not available on this platform",
    ))
}

// ---------------------------------------------------------------------------
// Cached metadata
// ---------------------------------------------------------------------------

/// Pre-computed HTTP caching metadata for a file. Avoids re-generating
/// ETags and formatting dates on every request.
#[derive(Clone, Debug)]
pub struct CachedMetadata {
    /// File size in bytes.
    pub size: u64,
    /// Last modification time.
    pub modified: SystemTime,
    /// Strong ETag: `"<size>-<mtime_epoch>"`.
    pub etag: String,
    /// RFC 7231 formatted Last-Modified header value.
    pub last_modified_http: String,
    /// MIME type (e.g. `"text/html; charset=utf-8"`).
    pub content_type: String,
}

impl CachedMetadata {
    /// Build metadata from a filesystem stat result.
    pub fn from_fs(path: &Path, meta: &std::fs::Metadata) -> Self {
        let size = meta.len();
        let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let mtime_secs = modified
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let etag = format!("\"{size}-{mtime_secs}\"");
        let last_modified_http = format_http_date(modified);
        let content_type = guess_content_type(path);

        Self {
            size,
            modified,
            etag,
            last_modified_http,
            content_type,
        }
    }

    /// Check If-None-Match against the cached ETag. Returns true if the
    /// client's cached version is still valid (→ 304 Not Modified).
    pub fn etag_matches(&self, if_none_match: &str) -> bool {
        // Strip surrounding quotes and whitespace for comparison.
        let client_etag = if_none_match.trim();
        client_etag == self.etag
            || client_etag == "*"
            || client_etag.trim_matches('"') == self.etag.trim_matches('"')
    }

    /// Check If-Modified-Since against the cached mtime. Returns true if
    /// the file has NOT been modified since the given date (→ 304).
    pub fn not_modified_since(&self, if_modified_since: &str) -> bool {
        if let Some(client_time) = parse_http_date(if_modified_since) {
            self.modified <= client_time
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// CachedEntry — single file in the cache
// ---------------------------------------------------------------------------

/// A cached file entry: metadata + optional mmap.
pub struct CachedEntry {
    pub metadata: CachedMetadata,
    /// Memory-mapped file data. `None` when mmap strategy is off or the
    /// file is too large / on a non-Unix platform.
    #[cfg(unix)]
    pub mmap: Option<Arc<MappedFile>>,
    /// Absolute path for re-validation.
    pub path: PathBuf,
    /// When this entry was last validated against disk (mtime check).
    pub validated_at: Instant,
}

impl CachedEntry {
    /// True if the entry's TTL has expired and should be re-validated.
    pub fn needs_revalidation(&self, ttl: Duration) -> bool {
        self.validated_at.elapsed() > ttl
    }

    /// Read file content as `Bytes` using the configured strategy.
    /// - Mmap: zero-copy from page cache.
    /// - Read: standard tokio::fs::read fallback.
    pub fn read_bytes(&self, offset: u64, len: u64) -> std::io::Result<Bytes> {
        #[cfg(unix)]
        if let Some(ref mmap) = self.mmap {
            return Ok(mmap_to_bytes(mmap, offset as usize, len as usize));
        }
        // Fallback: read from disk.
        let data = std::fs::read(&self.path)?;
        let end = (offset as usize + len as usize).min(data.len());
        let start = (offset as usize).min(end);
        Ok(Bytes::from(data[start..end].to_vec()))
    }

    /// Read the full file as `Bytes`.
    pub fn read_all(&self) -> std::io::Result<Bytes> {
        self.read_bytes(0, self.metadata.size)
    }
}

// ---------------------------------------------------------------------------
// FileCache
// ---------------------------------------------------------------------------

/// Configuration for the file descriptor / mmap cache.
#[derive(Clone, Debug)]
pub struct FileCacheConfig {
    /// Maximum number of cached entries. Default: 1024.
    pub max_entries: usize,
    /// Don't cache files larger than this (bytes). Default: 10 MB.
    pub max_file_size: u64,
    /// Time before re-checking file mtime on disk. Default: 2 seconds.
    pub revalidation_ttl: Duration,
    /// Whether to mmap files (Unix only). Default: true.
    pub use_mmap: bool,
}

impl Default for FileCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 1024,
            max_file_size: 10 * 1024 * 1024,
            revalidation_ttl: Duration::from_secs(2),
            use_mmap: true,
        }
    }
}

/// Performance counters for the file cache.
pub struct FileCacheMetrics {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub revalidations: AtomicU64,
    pub evictions: AtomicU64,
    pub mmap_serves: AtomicU64,
    pub read_serves: AtomicU64,
}

impl FileCacheMetrics {
    const fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            revalidations: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            mmap_serves: AtomicU64::new(0),
            read_serves: AtomicU64::new(0),
        }
    }
}

/// LRU-ish file descriptor and mmap cache. Caches open file metadata and
/// optionally memory-mapped regions for frequently accessed files.
///
/// Inspired by nginx's `open_file_cache` which keeps FDs warm for hot files,
/// eliminating `open()`/`stat()`/`close()` on every request.
pub struct FileCache {
    entries: DashMap<PathBuf, Arc<CachedEntry>, FastHasher>,
    config: FileCacheConfig,
    pub metrics: FileCacheMetrics,
}

impl FileCache {
    pub fn new(config: FileCacheConfig) -> Self {
        Self {
            entries: DashMap::with_hasher(FastHasher::default()),
            config,
            metrics: FileCacheMetrics::new(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(FileCacheConfig::default())
    }

    /// Look up a file, returning a cached entry if valid. On cache miss
    /// or TTL expiry, opens the file, caches metadata (and optionally
    /// mmap), then returns the new entry.
    pub fn get_or_open(&self, path: &Path) -> std::io::Result<Arc<CachedEntry>> {
        // Fast path: cache hit with valid TTL.
        if let Some(entry) = self.entries.get(path) {
            if !entry.needs_revalidation(self.config.revalidation_ttl) {
                self.metrics.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(Arc::clone(entry.value()));
            }
            // TTL expired — check if file changed.
            self.metrics.revalidations.fetch_add(1, Ordering::Relaxed);
            let disk_meta = std::fs::metadata(path)?;
            let disk_mtime = disk_meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            if disk_mtime == entry.metadata.modified && disk_meta.len() == entry.metadata.size {
                // File unchanged — refresh validation timestamp.
                // We can't mutate through DashMap ref, so re-insert with
                // updated timestamp.
                drop(entry);
                // Re-read to create fresh entry with updated validated_at.
                // In practice the mmap/FD are still valid.
                return self.insert_entry(path, disk_meta);
            }
            // File changed — remove stale entry and re-open.
            drop(entry);
            self.entries.remove(path);
        }

        self.metrics.misses.fetch_add(1, Ordering::Relaxed);

        // Evict if cache is full.
        if self.entries.len() >= self.config.max_entries {
            self.evict_oldest();
        }

        let meta = std::fs::metadata(path)?;
        self.insert_entry(path, meta)
    }

    /// Insert a new cache entry for the given file.
    fn insert_entry(
        &self,
        path: &Path,
        meta: std::fs::Metadata,
    ) -> std::io::Result<Arc<CachedEntry>> {
        let cached_meta = CachedMetadata::from_fs(path, &meta);

        #[cfg(unix)]
        let mmap = if self.config.use_mmap && meta.len() > 0 && meta.len() <= self.config.max_file_size
        {
            let file = std::fs::File::open(path)?;
            advise_sequential(&file);
            match MappedFile::new(file) {
                Ok(m) => Some(Arc::new(m)),
                Err(_) => None, // mmap failed — fall back to reads
            }
        } else {
            None
        };

        let entry = Arc::new(CachedEntry {
            metadata: cached_meta,
            #[cfg(unix)]
            mmap,
            path: path.to_path_buf(),
            validated_at: Instant::now(),
        });

        self.entries.insert(path.to_path_buf(), Arc::clone(&entry));
        Ok(entry)
    }

    /// Look up cached metadata without opening the file.
    pub fn get_metadata(&self, path: &Path) -> Option<CachedMetadata> {
        self.entries
            .get(path)
            .map(|e| e.value().metadata.clone())
    }

    /// Remove a specific entry.
    pub fn invalidate(&self, path: &Path) {
        self.entries.remove(path);
    }

    /// Clear all cached entries.
    pub fn clear(&self) {
        self.entries.clear();
    }

    /// Current number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Evict the entry with the oldest validation timestamp.
    fn evict_oldest(&self) {
        let mut oldest_path: Option<PathBuf> = None;
        let mut oldest_time = Instant::now();

        for entry in self.entries.iter() {
            if entry.value().validated_at < oldest_time {
                oldest_time = entry.value().validated_at;
                oldest_path = Some(entry.key().clone());
            }
        }

        if let Some(path) = oldest_path {
            self.entries.remove(&path);
            self.metrics.evictions.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP date formatting / parsing
// ---------------------------------------------------------------------------

/// Format a `SystemTime` as an RFC 7231 HTTP-date.
/// Example: `Sat, 01 Jan 2000 00:00:00 GMT`
pub fn format_http_date(time: SystemTime) -> String {
    let secs = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Simple UTC formatter — avoids pulling in chrono for this one use.
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Day-of-week calculation (Jan 1 1970 was Thursday = 4).
    let dow = ((days_since_epoch + 4) % 7) as usize;
    let dow_names = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

    // Date from days since epoch (civil calendar algorithm).
    let (year, month, day) = days_to_ymd(days_since_epoch as i64);
    let month_names = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
        "Nov", "Dec",
    ];

    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        dow_names[dow],
        day,
        month_names[(month - 1) as usize],
        year,
        hours,
        minutes,
        seconds,
    )
}

/// Parse an RFC 7231 HTTP-date into a `SystemTime`.
/// Supports the preferred format: `Sat, 01 Jan 2000 00:00:00 GMT`.
pub fn parse_http_date(s: &str) -> Option<SystemTime> {
    // Format: "Dow, DD Mon YYYY HH:MM:SS GMT"
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 6 {
        return None;
    }

    let day: u32 = parts[1].parse().ok()?;
    let month = match parts[2] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i64 = parts[3].parse().ok()?;
    let time_parts: Vec<&str> = parts[4].split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }
    let hours: u64 = time_parts[0].parse().ok()?;
    let minutes: u64 = time_parts[1].parse().ok()?;
    let seconds: u64 = time_parts[2].parse().ok()?;

    let days = ymd_to_days(year, month, day as i64);
    let total_secs = days as u64 * 86400 + hours * 3600 + minutes * 60 + seconds;

    Some(SystemTime::UNIX_EPOCH + Duration::from_secs(total_secs))
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: i64) -> (i64, i64, i64) {
    // Civil calendar algorithm from Howard Hinnant.
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Convert (year, month, day) to days since Unix epoch.
fn ymd_to_days(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Guess MIME type from file extension.
fn guess_content_type(path: &Path) -> String {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    match ext {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "br" => "application/x-brotli",
        "zst" => "application/zstd",
        "wasm" => "application/wasm",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "txt" => "text/plain; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",
        "yaml" | "yml" => "text/yaml; charset=utf-8",
        "toml" => "text/toml; charset=utf-8",
        "map" => "application/json",
        _ => "application/octet-stream",
    }
    .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_file(content: &[u8]) -> (tempfile::NamedTempFile, PathBuf) {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content).unwrap();
        f.flush().unwrap();
        let path = f.path().to_path_buf();
        (f, path)
    }

    // ── CachedMetadata ──

    #[test]
    fn metadata_etag_format() {
        let (_f, path) = temp_file(b"hello world");
        let meta = std::fs::metadata(&path).unwrap();
        let cached = CachedMetadata::from_fs(&path, &meta);

        assert!(cached.etag.starts_with('"'));
        assert!(cached.etag.ends_with('"'));
        assert!(cached.etag.contains('-'));
        assert_eq!(cached.size, 11);
    }

    #[test]
    fn metadata_etag_matches() {
        let (_f, path) = temp_file(b"test content");
        let meta = std::fs::metadata(&path).unwrap();
        let cached = CachedMetadata::from_fs(&path, &meta);

        assert!(cached.etag_matches(&cached.etag));
        assert!(cached.etag_matches("*"));
        assert!(!cached.etag_matches("\"different-etag\""));
    }

    #[test]
    fn metadata_if_modified_since() {
        let (_f, path) = temp_file(b"data");
        let meta = std::fs::metadata(&path).unwrap();
        let cached = CachedMetadata::from_fs(&path, &meta);

        // A date far in the future — file is NOT modified since then.
        assert!(cached.not_modified_since("Fri, 01 Jan 2100 00:00:00 GMT"));
        // A date in the past — file IS modified since then.
        assert!(!cached.not_modified_since("Thu, 01 Jan 1970 00:00:00 GMT"));
        // Invalid date — returns false (don't cache).
        assert!(!cached.not_modified_since("not a date"));
    }

    // ── HTTP date formatting/parsing ──

    #[test]
    fn http_date_roundtrip() {
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(946684800); // 2000-01-01
        let formatted = format_http_date(time);
        assert!(formatted.contains("2000"));
        assert!(formatted.contains("Jan"));
        assert!(formatted.ends_with("GMT"));

        let parsed = parse_http_date(&formatted).unwrap();
        let diff = parsed
            .duration_since(time)
            .or_else(|_| time.duration_since(parsed))
            .unwrap();
        assert!(diff.as_secs() < 2, "roundtrip drift: {:?}", diff);
    }

    #[test]
    fn parse_http_date_rfc7231() {
        let parsed = parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT");
        assert!(parsed.is_some());
    }

    #[test]
    fn parse_http_date_invalid() {
        assert!(parse_http_date("not a date").is_none());
        assert!(parse_http_date("").is_none());
    }

    // ── FileCache ──

    #[test]
    fn cache_insert_and_lookup() {
        let cache = FileCache::with_defaults();
        let (_f, path) = temp_file(b"cached content");

        let entry = cache.get_or_open(&path).unwrap();
        assert_eq!(entry.metadata.size, 14);
        assert_eq!(cache.len(), 1);

        // Second lookup should be a cache hit.
        let entry2 = cache.get_or_open(&path).unwrap();
        assert_eq!(entry2.metadata.etag, entry.metadata.etag);
        assert!(cache.metrics.hits.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn cache_invalidate() {
        let cache = FileCache::with_defaults();
        let (_f, path) = temp_file(b"to invalidate");

        cache.get_or_open(&path).unwrap();
        assert_eq!(cache.len(), 1);

        cache.invalidate(&path);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn cache_eviction_on_full() {
        let config = FileCacheConfig {
            max_entries: 2,
            ..Default::default()
        };
        let cache = FileCache::new(config);

        let (_f1, p1) = temp_file(b"file1");
        let (_f2, p2) = temp_file(b"file2");
        let (_f3, p3) = temp_file(b"file3");

        cache.get_or_open(&p1).unwrap();
        cache.get_or_open(&p2).unwrap();
        assert_eq!(cache.len(), 2);

        // Third file triggers eviction.
        cache.get_or_open(&p3).unwrap();
        assert!(cache.len() <= 2);
    }

    #[test]
    fn cache_read_bytes() {
        let cache = FileCache::with_defaults();
        let (_f, path) = temp_file(b"read me please");

        let entry = cache.get_or_open(&path).unwrap();
        let bytes = entry.read_all().unwrap();
        assert_eq!(&bytes[..], b"read me please");
    }

    #[test]
    fn cache_read_range() {
        let cache = FileCache::with_defaults();
        let (_f, path) = temp_file(b"0123456789ABCDEF");

        let entry = cache.get_or_open(&path).unwrap();
        let bytes = entry.read_bytes(4, 6).unwrap();
        assert_eq!(&bytes[..], b"456789");
    }

    // ── MappedFile (Unix only) ──

    #[cfg(unix)]
    #[test]
    fn mmap_read_full() {
        let (_f, path) = temp_file(b"memory mapped content");
        let file = std::fs::File::open(&path).unwrap();
        let mmap = MappedFile::new(file).unwrap();

        assert_eq!(mmap.len(), 21);
        assert_eq!(mmap.as_slice(), b"memory mapped content");
    }

    #[cfg(unix)]
    #[test]
    fn mmap_read_range() {
        let (_f, path) = temp_file(b"ABCDEFGHIJ");
        let file = std::fs::File::open(&path).unwrap();
        let mmap = MappedFile::new(file).unwrap();

        assert_eq!(mmap.range(3, 4), b"DEFG");
        assert_eq!(mmap.range(8, 100), b"IJ"); // clamped
    }

    #[cfg(unix)]
    #[test]
    fn mmap_to_bytes_zero_copy() {
        let (_f, path) = temp_file(b"zero copy test data");
        let file = std::fs::File::open(&path).unwrap();
        let mmap = Arc::new(MappedFile::new(file).unwrap());

        let bytes = mmap_to_bytes(&mmap, 5, 4);
        assert_eq!(&bytes[..], b"copy");

        let bytes2 = mmap_to_bytes(&mmap, 0, mmap.len());
        assert_eq!(&bytes2[..], b"zero copy test data");
    }

    #[cfg(unix)]
    #[test]
    fn mmap_empty_file_error() {
        let (_f, path) = temp_file(b"");
        let file = std::fs::File::open(&path).unwrap();
        assert!(MappedFile::new(file).is_err());
    }

    // ── MIME type guessing ──

    #[test]
    fn content_type_guessing() {
        assert_eq!(guess_content_type(Path::new("style.css")), "text/css; charset=utf-8");
        assert_eq!(guess_content_type(Path::new("app.js")), "application/javascript; charset=utf-8");
        assert_eq!(guess_content_type(Path::new("image.png")), "image/png");
        assert_eq!(guess_content_type(Path::new("video.mp4")), "video/mp4");
        assert_eq!(guess_content_type(Path::new("unknown.xyz")), "application/octet-stream");
    }

    // ── Strategy toggles ──

    #[test]
    fn file_serve_strategy_toggle() {
        set_file_serve_strategy(FileServeStrategy::Read);
        assert_eq!(file_serve_strategy(), FileServeStrategy::Read);

        set_file_serve_strategy(FileServeStrategy::Mmap);
        assert_eq!(file_serve_strategy(), FileServeStrategy::Mmap);

        set_file_serve_strategy(FileServeStrategy::Sendfile);
        assert_eq!(file_serve_strategy(), FileServeStrategy::Sendfile);
    }

    #[test]
    fn directory_listing_disabled_by_default() {
        // Security: directory listing must be off by default.
        assert!(!DIRECTORY_LISTING_ENABLED.load(Ordering::Relaxed));
    }

    #[test]
    fn file_cache_enabled_by_default() {
        assert!(FILE_CACHE_ENABLED.load(Ordering::Relaxed));
    }

    // ── Page cache advisor (smoke test) ──

    #[test]
    fn advise_does_not_crash() {
        let (_f, path) = temp_file(b"page cache test");
        let file = std::fs::File::open(&path).unwrap();
        advise_sequential(&file);
        advise_willneed(&file, 0, 15);
        advise_dontneed(&file, 0, 15);
        // Just verifying no panics / segfaults.
    }

    // ── ymd_to_days / days_to_ymd ──

    #[test]
    fn civil_date_roundtrip() {
        // Unix epoch.
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
        assert_eq!(ymd_to_days(1970, 1, 1), 0);

        // 2000-01-01.
        let d = ymd_to_days(2000, 1, 1);
        assert_eq!(days_to_ymd(d), (2000, 1, 1));

        // 2024-02-29 (leap year).
        let d = ymd_to_days(2024, 2, 29);
        assert_eq!(days_to_ymd(d), (2024, 2, 29));
    }

    // ── FileServeStrategy — repr(u8) roundtrip ──

    #[test]
    fn file_serve_strategy_repr_u8_values() {
        assert_eq!(FileServeStrategy::Read as u8, 0);
        assert_eq!(FileServeStrategy::Mmap as u8, 1);
        assert_eq!(FileServeStrategy::Sendfile as u8, 2);
    }

    #[test]
    fn file_serve_strategy_from_u8_roundtrip() {
        assert_eq!(FileServeStrategy::from_u8(0), FileServeStrategy::Read);
        assert_eq!(FileServeStrategy::from_u8(1), FileServeStrategy::Mmap);
        assert_eq!(FileServeStrategy::from_u8(2), FileServeStrategy::Sendfile);
        // Unknown values fall back to Read.
        assert_eq!(FileServeStrategy::from_u8(3), FileServeStrategy::Read);
        assert_eq!(FileServeStrategy::from_u8(255), FileServeStrategy::Read);
    }

    // ── DirectoryListing toggle ──

    #[test]
    fn directory_listing_toggle() {
        set_directory_listing_enabled(true);
        assert!(is_directory_listing_enabled());
        set_directory_listing_enabled(false);
        assert!(!is_directory_listing_enabled());
    }

    // ── MappedFile additional tests (Unix) ──

    #[cfg(unix)]
    #[test]
    fn mmap_len_and_not_empty() {
        let (_f, path) = temp_file(b"not empty");
        let file = std::fs::File::open(&path).unwrap();
        let mmap = MappedFile::new(file).unwrap();
        assert_eq!(mmap.len(), 9);
        assert!(!mmap.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn mmap_range_start_zero_full_read() {
        let content = b"full read from zero";
        let (_f, path) = temp_file(content);
        let file = std::fs::File::open(&path).unwrap();
        let mmap = MappedFile::new(file).unwrap();
        // offset=0, len=full length is equivalent to as_slice()
        assert_eq!(mmap.range(0, content.len()), content.as_slice());
    }

    #[cfg(unix)]
    #[test]
    fn mmap_range_start_beyond_len_returns_empty() {
        let (_f, path) = temp_file(b"short");
        let file = std::fs::File::open(&path).unwrap();
        let mmap = MappedFile::new(file).unwrap();
        // offset past the end => clamped to empty slice
        assert_eq!(mmap.range(999, 10), b"");
    }

    #[cfg(unix)]
    #[test]
    fn mmap_to_bytes_full_content() {
        let content = b"bytes from mmap";
        let (_f, path) = temp_file(content);
        let file = std::fs::File::open(&path).unwrap();
        let mmap = Arc::new(MappedFile::new(file).unwrap());
        let bytes = mmap_to_bytes(&mmap, 0, mmap.len());
        assert_eq!(&bytes[..], content.as_slice());
    }

    // ── CachedMetadata additional tests ──

    #[test]
    fn metadata_from_fs_populates_all_fields() {
        let (_f, path) = temp_file(b"hello");
        let meta = std::fs::metadata(&path).unwrap();
        let cached = CachedMetadata::from_fs(&path, &meta);
        assert_eq!(cached.size, 5);
        assert!(!cached.etag.is_empty());
        assert!(!cached.last_modified_http.is_empty());
        assert!(!cached.content_type.is_empty());
        // modified should be recent (not UNIX_EPOCH)
        assert!(cached.modified > SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn metadata_etag_matches_without_quotes() {
        let (_f, path) = temp_file(b"etag test");
        let meta = std::fs::metadata(&path).unwrap();
        let cached = CachedMetadata::from_fs(&path, &meta);
        // The etag is stored with quotes e.g. "\"9-1234567\"".
        // etag_matches should match the raw inner value without quotes too.
        let inner = cached.etag.trim_matches('"');
        assert!(cached.etag_matches(inner));
    }

    #[test]
    fn metadata_etag_does_not_match_random_string() {
        let (_f, path) = temp_file(b"no match");
        let meta = std::fs::metadata(&path).unwrap();
        let cached = CachedMetadata::from_fs(&path, &meta);
        assert!(!cached.etag_matches("\"99999-0\""));
        assert!(!cached.etag_matches("garbage"));
    }

    // ── content_type for various extensions ──

    #[test]
    fn content_type_html_css_js_json() {
        assert_eq!(guess_content_type(Path::new("index.html")), "text/html; charset=utf-8");
        assert_eq!(guess_content_type(Path::new("page.htm")), "text/html; charset=utf-8");
        assert_eq!(guess_content_type(Path::new("style.css")), "text/css; charset=utf-8");
        assert_eq!(guess_content_type(Path::new("bundle.js")), "application/javascript; charset=utf-8");
        assert_eq!(guess_content_type(Path::new("data.json")), "application/json; charset=utf-8");
    }

    #[test]
    fn content_type_images_and_fonts() {
        assert_eq!(guess_content_type(Path::new("logo.png")), "image/png");
        assert_eq!(guess_content_type(Path::new("photo.jpg")), "image/jpeg");
        assert_eq!(guess_content_type(Path::new("photo.jpeg")), "image/jpeg");
        assert_eq!(guess_content_type(Path::new("icon.svg")), "image/svg+xml");
        assert_eq!(guess_content_type(Path::new("font.woff2")), "font/woff2");
        assert_eq!(guess_content_type(Path::new("font.woff")), "font/woff");
    }

    #[test]
    fn content_type_unknown_extension() {
        assert_eq!(guess_content_type(Path::new("file.zzz")), "application/octet-stream");
        assert_eq!(guess_content_type(Path::new("noext")), "application/octet-stream");
    }

    // ── FileCache additional tests ──

    #[test]
    fn cache_is_empty_after_creation() {
        let cache = FileCache::with_defaults();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn cache_get_metadata_returns_none_for_missing() {
        let cache = FileCache::with_defaults();
        assert!(cache.get_metadata(Path::new("/nonexistent/file.txt")).is_none());
    }

    #[test]
    fn cache_get_metadata_returns_some_after_insert() {
        let cache = FileCache::with_defaults();
        let (_f, path) = temp_file(b"metadata test");
        cache.get_or_open(&path).unwrap();
        let meta = cache.get_metadata(&path);
        assert!(meta.is_some());
        assert_eq!(meta.unwrap().size, 13);
    }

    #[test]
    fn cache_clear_removes_all() {
        let cache = FileCache::with_defaults();
        let (_f1, p1) = temp_file(b"one");
        let (_f2, p2) = temp_file(b"two");
        cache.get_or_open(&p1).unwrap();
        cache.get_or_open(&p2).unwrap();
        assert_eq!(cache.len(), 2);
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_eviction_increments_metric() {
        let config = FileCacheConfig {
            max_entries: 1,
            ..Default::default()
        };
        let cache = FileCache::new(config);
        let (_f1, p1) = temp_file(b"evict1");
        let (_f2, p2) = temp_file(b"evict2");
        cache.get_or_open(&p1).unwrap();
        cache.get_or_open(&p2).unwrap();
        assert!(cache.metrics.evictions.load(Ordering::Relaxed) >= 1);
    }

    // ── http_date / parse_http_date with known dates ──

    #[test]
    fn format_http_date_epoch() {
        let formatted = format_http_date(SystemTime::UNIX_EPOCH);
        assert_eq!(formatted, "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn format_http_date_y2k() {
        // 2000-01-01 00:00:00 UTC = 946684800 seconds since epoch
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(946684800);
        let formatted = format_http_date(time);
        assert_eq!(formatted, "Sat, 01 Jan 2000 00:00:00 GMT");
    }

    #[test]
    fn parse_http_date_known_value() {
        let parsed = parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT").unwrap();
        assert_eq!(parsed, SystemTime::UNIX_EPOCH);
    }

    // ── civil_date formatting ──

    #[test]
    fn civil_date_end_of_year() {
        let d = ymd_to_days(1999, 12, 31);
        assert_eq!(days_to_ymd(d), (1999, 12, 31));
    }

    #[test]
    fn civil_date_century_boundary() {
        // 1900 is NOT a leap year (divisible by 100 but not 400)
        let d = ymd_to_days(1900, 3, 1);
        assert_eq!(days_to_ymd(d), (1900, 3, 1));
        // 2000 IS a leap year
        let d = ymd_to_days(2000, 2, 29);
        assert_eq!(days_to_ymd(d), (2000, 2, 29));
    }

    // ── sendfile stub (non-Linux) ──

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn sendfile_unsupported_on_non_linux() {
        let result = sendfile_transfer(0, 0, &mut 0i64, 0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Unsupported);
    }
}
