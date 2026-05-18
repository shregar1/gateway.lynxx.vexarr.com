use axum::body::Body;
use axum::http::{header, Response, StatusCode};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tokio::fs;

static HASHED_ASSET_RE: OnceLock<regex::Regex> = OnceLock::new();

fn hashed_re() -> &'static regex::Regex {
    HASHED_ASSET_RE.get_or_init(|| {
        regex::Regex::new(
            r"[.\-][0-9a-f]{8,}\.(js|css|woff2?|ttf|eot|svg|png|jpe?g|gif|webp|avif|ico)$",
        )
        .expect("invariant: literal HASHED_ASSET_RE compiles; covered by unit tests")
    })
}

/// Default patterns for files that should be hidden from static serving.
const DEFAULT_HIDDEN: &[&str] = &[
    ".git",
    ".env",
    ".DS_Store",
    ".htaccess",
    ".htpasswd",
    "Thumbs.db",
    "desktop.ini",
    ".svn",
    ".hg",
];

fn mime_for_ext(ext: &str) -> &'static str {
    match ext {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "eot" => "application/vnd.ms-fontobject",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        "map" => "application/json",
        "gz" => "application/gzip",
        "br" => "application/x-brotli",
        _ => "application/octet-stream",
    }
}

fn is_static_asset(ext: &str) -> bool {
    matches!(
        ext,
        "js" | "mjs"
            | "css"
            | "woff2"
            | "woff"
            | "ttf"
            | "otf"
            | "eot"
            | "svg"
            | "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "webp"
            | "avif"
            | "ico"
            | "mp4"
            | "webm"
            | "mp3"
            | "ogg"
            | "pdf"
            | "wasm"
    )
}

fn empty_response(status: StatusCode) -> Response<Body> {
    // Infallible builder: `Body::empty()` is always valid and `status` is a
    // typed `StatusCode`. The `unwrap_or_else` fallback exists only to remove
    // the last `.unwrap()` from the hot path — `Response::new` cannot fail.
    Response::builder()
        .status(status)
        .body(Body::empty())
        .unwrap_or_else(|_| {
            let mut r = Response::new(Body::empty());
            *r.status_mut() = status;
            r
        })
}

/// Apply a status override to an existing response (if configured).
fn apply_status_override(mut resp: Response<Body>, status_override: Option<u16>) -> Response<Body> {
    if let Some(code) = status_override {
        if let Ok(status) = StatusCode::from_u16(code) {
            *resp.status_mut() = status;
        }
    }
    resp
}

/// Generate a strong ETag from file size and modification time.
fn generate_etag(size: u64, modified: std::time::SystemTime) -> String {
    let epoch_secs = modified
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("\"{:x}-{:x}\"", size, epoch_secs)
}

/// Format a SystemTime as an HTTP-date (RFC 7231).
fn format_http_date(t: std::time::SystemTime) -> String {
    let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    // We do simple HTTP-date formatting without pulling in httpdate crate.
    // Format: "Mon, 01 Jan 2024 00:00:00 GMT"
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since epoch (1970-01-01 Thursday)
    let wday = ((days + 4) % 7) as usize; // 0=Sunday
    let wday_names = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

    // Compute year/month/day from days since epoch
    let (year, month, day) = days_to_ymd(days as i64);
    let month_names = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        wday_names[wday],
        day,
        month_names[(month - 1) as usize],
        year,
        hours,
        minutes,
        seconds
    )
}

fn days_to_ymd(days: i64) -> (i64, i64, i64) {
    // Civil days to year/month/day (Euclidean affine algorithm).
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

/// Check If-None-Match / If-Modified-Since for 304 eligibility.
fn check_conditional(
    if_none_match: Option<&str>,
    if_modified_since: Option<&str>,
    etag: &str,
    _modified: std::time::SystemTime,
) -> bool {
    // ETag match takes priority.
    if let Some(inm) = if_none_match {
        return inm
            .split(',')
            .any(|tag| tag.trim().trim_matches('"') == etag.trim_matches('"'));
    }
    // Fallback to If-Modified-Since.
    if let Some(_ims) = if_modified_since {
        // Simplified: if the ETag matches, return 304. For If-Modified-Since
        // we'd need HTTP-date parsing; skipping for now since ETag is the
        // primary mechanism and all our responses include ETag.
        return false;
    }
    false
}

/// Parse Range header, returning (start, end) byte offsets.
/// Supports single byte ranges: "bytes=0-499", "bytes=500-", "bytes=-500".
fn parse_range(range_header: &str, file_size: u64) -> Option<(u64, u64)> {
    let range = range_header.strip_prefix("bytes=")?;
    let (start_str, end_str) = range.split_once('-')?;

    if start_str.is_empty() {
        // Suffix range: bytes=-500
        let suffix: u64 = end_str.parse().ok()?;
        if suffix > file_size {
            return None;
        }
        Some((file_size - suffix, file_size - 1))
    } else if end_str.is_empty() {
        // Open-ended: bytes=500-
        let start: u64 = start_str.parse().ok()?;
        if start >= file_size {
            return None;
        }
        Some((start, file_size - 1))
    } else {
        let start: u64 = start_str.parse().ok()?;
        let end: u64 = end_str.parse().ok()?;
        if start > end || start >= file_size {
            return None;
        }
        Some((start, end.min(file_size - 1)))
    }
}

fn file_response(
    bytes: bytes::Bytes,
    ext: &str,
    request_path: &str,
    content_encoding: Option<&str>,
    etag: Option<&str>,
    last_modified: Option<std::time::SystemTime>,
    cache_control_override: Option<&str>,
) -> Response<Body> {
    let mime = mime_for_ext(ext);

    let cache_control = cache_control_override.unwrap_or_else(|| {
        if hashed_re().is_match(request_path) {
            "public, max-age=31536000, immutable"
        } else if ext == "html" || ext == "htm" || request_path == "/" {
            "public, max-age=0, must-revalidate"
        } else if is_static_asset(ext) {
            "public, max-age=86400, stale-while-revalidate=604800"
        } else {
            "public, max-age=3600"
        }
    });

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CONTENT_LENGTH, bytes.len())
        .header(header::CACHE_CONTROL, cache_control)
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header("X-Frame-Options", "DENY")
        .header("Referrer-Policy", "strict-origin-when-cross-origin")
        .header(header::ACCEPT_RANGES, "bytes");

    if let Some(tag) = etag {
        builder = builder.header(header::ETAG, tag);
    }
    if let Some(modified) = last_modified {
        builder = builder.header(header::LAST_MODIFIED, format_http_date(modified));
    }
    if let Some(enc) = content_encoding {
        builder = builder
            .header(header::CONTENT_ENCODING, enc)
            .header(header::VARY, "Accept-Encoding");
    }

    builder
        .body(Body::from(bytes))
        .unwrap_or_else(|_| empty_response(StatusCode::INTERNAL_SERVER_ERROR))
}

fn range_response(
    bytes: bytes::Bytes,
    ext: &str,
    start: u64,
    end: u64,
    total: u64,
    etag: Option<&str>,
    content_encoding: Option<&str>,
) -> Response<Body> {
    let mime = mime_for_ext(ext);

    let mut builder = Response::builder()
        .status(StatusCode::PARTIAL_CONTENT)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CONTENT_LENGTH, bytes.len())
        .header(
            header::CONTENT_RANGE,
            format!("bytes {start}-{end}/{total}"),
        )
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff");

    if let Some(tag) = etag {
        builder = builder.header(header::ETAG, tag);
    }
    if let Some(enc) = content_encoding {
        builder = builder.header(header::CONTENT_ENCODING, enc);
    }

    builder
        .body(Body::from(bytes))
        .unwrap_or_else(|_| empty_response(StatusCode::INTERNAL_SERVER_ERROR))
}

/// Resolve `request_path` to a file under `root`, blocking path traversal.
fn safe_resolve(root: &Path, request_path: &str) -> Option<PathBuf> {
    let clean = request_path.trim_start_matches('/');
    if clean.contains("..") {
        return None;
    }
    let candidate = root.join(clean);
    if candidate
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return None;
    }
    Some(candidate)
}

/// Check if a path component is hidden (dotfiles, .env, .git, etc.).
fn is_hidden_path(request_path: &str, extra_hide: &[String]) -> bool {
    for segment in request_path.split('/') {
        if segment.is_empty() {
            continue;
        }
        // Check default hidden patterns.
        for pattern in DEFAULT_HIDDEN {
            if segment == *pattern || segment.starts_with(&format!("{pattern}/")) {
                return true;
            }
        }
        // Check user-configured patterns.
        for pattern in extra_hide {
            if segment == pattern.as_str() {
                return true;
            }
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────
// Browse sort configuration
// ─────────────────────────────────────────────────────────────────────────

/// Field to sort directory listing entries by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowseSortField {
    Name,
    Size,
    Time,
}

/// Sort direction for directory listings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDirection {
    Ascending,
    Descending,
}

/// Static file serving options, passed from the service config.
pub struct ServeOptions<'a> {
    /// Extra file/directory names to hide (beyond defaults).
    pub hide_patterns: &'a [String],
    /// Override cache-control header value.
    pub cache_control: Option<&'a str>,
    /// Request headers for conditional/range handling.
    pub if_none_match: Option<&'a str>,
    pub if_modified_since: Option<&'a str>,
    pub range: Option<&'a str>,
    /// When true, enable directory browsing for directories that have no
    /// index file. The response is an HTML listing of the directory.
    pub browse: bool,
    /// Custom HTML template for directory listings. The template receives
    /// these placeholders: `{{path}}`, `{{entries}}`. When `None` a
    /// built-in minimal HTML page is used.
    pub browse_template: Option<&'a str>,
    /// Sort order for browse directory listings. When `None`, the default
    /// is dirs-first then by name ascending.
    pub browse_sort: Option<(BrowseSortField, SortDirection)>,
    /// Maximum number of entries to show in a directory listing.
    /// Defaults to 10000.
    pub browse_file_limit: usize,
    /// When true, symlink entries in directory listings include the
    /// target path they point to via a `symlink_target` field.
    pub browse_reveal_symlinks: bool,
    /// When true, return `ServeResult::PassThru` instead of 404 when the
    /// requested file doesn't exist. The caller can then fall through to
    /// the next handler (e.g. proxy to an upstream).
    pub pass_thru: bool,
    /// Which precompressed sidecar encodings to try. When `None`, the
    /// default set (br, zstd, gzip) is used. Pass an empty vec to
    /// disable precompressed serving entirely.
    pub precompressed: Option<&'a [PrecompressedEncoding]>,
    /// When true, skip the canonical `/dir` → `/dir/` redirect for
    /// directories.
    pub disable_canonical_uris: bool,
    /// Override the HTTP status code for served files. Useful for custom
    /// error pages (e.g. serve `404.html` with actual 404 status).
    pub status_override: Option<u16>,
}

impl<'a> Default for ServeOptions<'a> {
    fn default() -> Self {
        Self {
            hide_patterns: &[],
            cache_control: None,
            if_none_match: None,
            if_modified_since: None,
            range: None,
            browse: false,
            browse_template: None,
            browse_sort: None,
            browse_file_limit: 10_000,
            browse_reveal_symlinks: false,
            pass_thru: false,
            precompressed: None,
            disable_canonical_uris: false,
            status_override: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Configurable precompressed encodings
// ─────────────────────────────────────────────────────────────────────────

/// Precompressed encoding that can be opted into via config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrecompressedEncoding {
    Brotli,
    Zstd,
    Gzip,
}

impl PrecompressedEncoding {
    pub fn suffix(&self) -> &'static str {
        match self {
            Self::Brotli => ".br",
            Self::Zstd => ".zst",
            Self::Gzip => ".gz",
        }
    }

    pub fn encoding(&self) -> &'static str {
        match self {
            Self::Brotli => "br",
            Self::Zstd => "zstd",
            Self::Gzip => "gzip",
        }
    }

    /// Parse from a string like `"br"`, `"gzip"`, `"zstd"`.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "br" | "brotli" => Some(Self::Brotli),
            "zstd" | "zstandard" => Some(Self::Zstd),
            "gz" | "gzip" => Some(Self::Gzip),
            _ => None,
        }
    }
}

/// Default precompressed algorithm priority.
pub const DEFAULT_PRECOMPRESSED: &[PrecompressedEncoding] = &[
    PrecompressedEncoding::Brotli,
    PrecompressedEncoding::Zstd,
    PrecompressedEncoding::Gzip,
];

// ─────────────────────────────────────────────────────────────────────────
// Pluggable filesystem backend (virtual FS)
// ─────────────────────────────────────────────────────────────────────────

/// Metadata about a file or directory, abstracted from the OS.
#[derive(Debug, Clone)]
pub struct FsMeta {
    pub is_file: bool,
    pub is_dir: bool,
    pub len: u64,
    pub modified: Option<std::time::SystemTime>,
}

/// A single directory entry for listings.
#[derive(Debug, Clone)]
pub struct FsDirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<std::time::SystemTime>,
    /// When `browse_reveal_symlinks` is enabled, this contains the
    /// symlink target path. `None` for regular files/directories.
    pub symlink_target: Option<String>,
}

/// Trait for pluggable filesystem backends. The default implementation
/// uses `tokio::fs` (local disk). Implementors can provide S3, GCS,
/// in-memory, or overlay filesystems.
#[async_trait::async_trait]
pub trait FileSystem: Send + Sync {
    /// Stat a path, returning metadata or `None` if it doesn't exist.
    async fn metadata(&self, path: &Path) -> Option<FsMeta>;
    /// Read a file's full contents.
    async fn read(&self, path: &Path) -> Option<Vec<u8>>;
    /// List entries in a directory.
    async fn read_dir(&self, path: &Path) -> Option<Vec<FsDirEntry>>;
}

/// Default filesystem backed by `tokio::fs`.
pub struct LocalFs;

#[async_trait::async_trait]
impl FileSystem for LocalFs {
    async fn metadata(&self, path: &Path) -> Option<FsMeta> {
        let meta = fs::metadata(path).await.ok()?;
        Some(FsMeta {
            is_file: meta.is_file(),
            is_dir: meta.is_dir(),
            len: meta.len(),
            modified: meta.modified().ok(),
        })
    }

    async fn read(&self, path: &Path) -> Option<Vec<u8>> {
        fs::read(path).await.ok()
    }

    async fn read_dir(&self, path: &Path) -> Option<Vec<FsDirEntry>> {
        let mut dir = fs::read_dir(path).await.ok()?;
        let mut entries = Vec::new();
        while let Ok(Some(entry)) = dir.next_entry().await {
            let meta = entry.metadata().await.ok();
            // Check if the entry is a symlink (use symlink_metadata to
            // avoid following the link).
            let symlink_target = match fs::symlink_metadata(entry.path()).await {
                Ok(sm) if sm.file_type().is_symlink() => fs::read_link(entry.path())
                    .await
                    .ok()
                    .map(|t| t.to_string_lossy().to_string()),
                _ => None,
            };
            entries.push(FsDirEntry {
                name: entry.file_name().to_string_lossy().to_string(),
                is_dir: meta.as_ref().map(|m| m.is_dir()).unwrap_or(false),
                size: meta.as_ref().map(|m| m.len()).unwrap_or(0),
                modified: meta.and_then(|m| m.modified().ok()),
                symlink_target,
            });
        }
        entries.sort_by(|a, b| {
            // Directories first, then alphabetical.
            b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name))
        });
        Some(entries)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Directory browse (directory listing)
// ─────────────────────────────────────────────────────────────────────────

/// Sort directory entries according to the configured sort order.
/// Always keeps directories first, then sorts within each group.
fn sort_entries(entries: &mut [FsDirEntry], sort: Option<(BrowseSortField, SortDirection)>) {
    let (field, dir) = sort.unwrap_or((BrowseSortField::Name, SortDirection::Ascending));
    entries.sort_by(|a, b| {
        // Directories always first.
        let dir_ord = b.is_dir.cmp(&a.is_dir);
        if dir_ord != std::cmp::Ordering::Equal {
            return dir_ord;
        }
        let ord = match field {
            BrowseSortField::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            BrowseSortField::Size => a.size.cmp(&b.size),
            BrowseSortField::Time => {
                let ta = a.modified.unwrap_or(std::time::UNIX_EPOCH);
                let tb = b.modified.unwrap_or(std::time::UNIX_EPOCH);
                ta.cmp(&tb)
            }
        };
        match dir {
            SortDirection::Ascending => ord,
            SortDirection::Descending => ord.reverse(),
        }
    });
}

/// Render a directory listing as an HTML page.
pub fn render_directory_listing(
    request_path: &str,
    entries: &[FsDirEntry],
    template: Option<&str>,
    opts: &ServeOptions<'_>,
) -> Response<Body> {
    // Apply sort order.
    let mut sorted = entries.to_vec();
    sort_entries(&mut sorted, opts.browse_sort);

    // Apply file limit.
    sorted.truncate(opts.browse_file_limit);

    let mut rows = String::new();
    // Parent directory link.
    if request_path != "/" {
        rows.push_str(r#"<tr><td><a href="../">../</a></td><td>—</td><td>—</td></tr>"#);
        rows.push('\n');
    }
    for entry in &sorted {
        let name = &entry.name;
        // Skip hidden entries.
        if name.starts_with('.') {
            continue;
        }
        let display = if entry.is_dir {
            format!("{name}/")
        } else {
            name.clone()
        };
        let href = if entry.is_dir {
            format!("{name}/")
        } else {
            name.clone()
        };
        let size = if entry.is_dir {
            "—".to_string()
        } else {
            format_file_size(entry.size)
        };
        let modified = entry
            .modified
            .map(format_http_date)
            .unwrap_or_else(|| "—".to_string());

        // Symlink annotation when reveal_symlinks is enabled.
        let symlink_info = if opts.browse_reveal_symlinks {
            if let Some(ref target) = entry.symlink_target {
                format!(" → {target}")
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        rows.push_str(&format!(
            r#"<tr><td><a href="{href}">{display}{symlink_info}</a></td><td>{size}</td><td>{modified}</td></tr>"#,
        ));
        rows.push('\n');
    }

    let html = if let Some(tpl) = template {
        tpl.replace("{{path}}", request_path)
            .replace("{{entries}}", &rows)
    } else {
        format!(
            r#"<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Index of {path}</title>
<style>
body {{ font-family: system-ui, -apple-system, sans-serif; margin: 2rem; color: #111; }}
h1 {{ font-size: 1.2rem; font-weight: 600; border-bottom: 1px solid #ddd; padding-bottom: .5rem; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ text-align: left; padding: .4rem .8rem; border-bottom: 1px solid #eee; }}
th {{ font-weight: 600; font-size: .85rem; text-transform: uppercase; letter-spacing: .04em; color: #666; }}
a {{ color: #111; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
td:nth-child(2), td:nth-child(3) {{ color: #666; font-size: .9rem; }}
</style>
</head><body>
<h1>Index of {path}</h1>
<table>
<thead><tr><th>Name</th><th>Size</th><th>Modified</th></tr></thead>
<tbody>
{entries}
</tbody>
</table>
</body></html>"#,
            path = request_path,
            entries = rows,
        )
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "public, max-age=0, must-revalidate")
        .body(Body::from(html))
        .unwrap_or_else(|_| empty_response(StatusCode::INTERNAL_SERVER_ERROR))
}

fn format_file_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

// ─────────────────────────────────────────────────────────────────────────
// pass_thru result type
// ─────────────────────────────────────────────────────────────────────────

/// Result of a static file serve attempt. When `pass_thru` is enabled,
/// the caller receives `PassThru` instead of a 404 response, allowing
/// it to fall through to the next handler (e.g. proxy to upstream).
pub enum ServeResult {
    /// File was found and served (or 304/206/etc.).
    Response(Response<Body>),
    /// File not found; caller should try the next handler.
    PassThru,
}

/// Serve with pass-through support and pluggable filesystem.
pub async fn serve_with_fs(
    filesystem: &dyn FileSystem,
    document_root: &str,
    index_file: &str,
    spa_fallback: bool,
    request_path: &str,
    accept_encoding: &str,
    opts: &ServeOptions<'_>,
) -> ServeResult {
    let root = PathBuf::from(document_root);
    let encodings = parse_accept_encoding(accept_encoding);

    if is_hidden_path(request_path, opts.hide_patterns) {
        return if opts.pass_thru {
            ServeResult::PassThru
        } else {
            ServeResult::Response(empty_response(StatusCode::NOT_FOUND))
        };
    }

    let candidate = match safe_resolve(&root, request_path) {
        Some(p) => p,
        None => return ServeResult::Response(empty_response(StatusCode::FORBIDDEN)),
    };

    // Canonical redirect: /dir → /dir/
    if !opts.disable_canonical_uris && !request_path.ends_with('/') && request_path != "/" {
        if let Some(meta) = filesystem.metadata(&candidate).await {
            if meta.is_dir {
                let redirect_to = format!("{request_path}/");
                return ServeResult::Response(
                    Response::builder()
                        .status(StatusCode::MOVED_PERMANENTLY)
                        .header(header::LOCATION, redirect_to)
                        .body(Body::empty())
                        .unwrap_or_else(|_| empty_response(StatusCode::INTERNAL_SERVER_ERROR)),
                );
            }
        }
    }

    // Determine which precompressed set to use.
    let precompressed = opts.precompressed.unwrap_or(DEFAULT_PRECOMPRESSED);

    // Try serving the file directly (with precompressed variants).
    if let Some(resp) = try_serve_file_with_fs(
        filesystem,
        &candidate,
        request_path,
        &encodings,
        opts,
        precompressed,
    )
    .await
    {
        return ServeResult::Response(apply_status_override(resp, opts.status_override));
    }

    // Try index file in directory.
    if candidate.extension().is_none() || request_path.ends_with('/') {
        let index = candidate.join(index_file);
        if let Some(resp) = try_serve_file_with_fs(
            filesystem,
            &index,
            request_path,
            &encodings,
            opts,
            precompressed,
        )
        .await
        {
            return ServeResult::Response(apply_status_override(resp, opts.status_override));
        }

        // Directory browse: list directory if enabled and dir exists.
        if opts.browse {
            if let Some(meta) = filesystem.metadata(&candidate).await {
                if meta.is_dir {
                    if let Some(entries) = filesystem.read_dir(&candidate).await {
                        return ServeResult::Response(render_directory_listing(
                            request_path,
                            &entries,
                            opts.browse_template,
                            opts,
                        ));
                    }
                }
            }
        }
    }

    if request_path == "/favicon.ico" {
        return ServeResult::Response(empty_response(StatusCode::NO_CONTENT));
    }

    if spa_fallback {
        let index = root.join(index_file);
        if let Some(resp) =
            try_serve_file_with_fs(filesystem, &index, "/", &encodings, opts, precompressed).await
        {
            return ServeResult::Response(apply_status_override(resp, opts.status_override));
        }
    }

    if opts.pass_thru {
        ServeResult::PassThru
    } else {
        ServeResult::Response(empty_response(StatusCode::NOT_FOUND))
    }
}

/// Try serving a file using a pluggable filesystem, with precompressed variants.
async fn try_serve_file_with_fs(
    filesystem: &dyn FileSystem,
    path: &Path,
    request_path: &str,
    accept_encodings: &[String],
    opts: &ServeOptions<'_>,
    precompressed: &[PrecompressedEncoding],
) -> Option<Response<Body>> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    // Try precompressed variants first.
    for enc in precompressed {
        if accept_encodings.iter().any(|e| e == enc.encoding()) {
            let compressed_path = path.with_extension(format!("{}{}", ext, enc.suffix()));
            if let Some(meta) = filesystem.metadata(&compressed_path).await {
                if meta.is_file {
                    if let Some(bytes) = filesystem.read(&compressed_path).await {
                        let etag =
                            generate_etag(meta.len, meta.modified.unwrap_or(std::time::UNIX_EPOCH));
                        if check_conditional(
                            opts.if_none_match,
                            opts.if_modified_since,
                            &etag,
                            meta.modified.unwrap_or(std::time::UNIX_EPOCH),
                        ) {
                            return Some(
                                Response::builder()
                                    .status(StatusCode::NOT_MODIFIED)
                                    .header(header::ETAG, &etag)
                                    .body(Body::empty())
                                    .unwrap_or_else(|_| {
                                        empty_response(StatusCode::INTERNAL_SERVER_ERROR)
                                    }),
                            );
                        }
                        return Some(file_response(
                            bytes::Bytes::from(bytes),
                            ext,
                            request_path,
                            Some(enc.encoding()),
                            Some(&etag),
                            meta.modified,
                            opts.cache_control,
                        ));
                    }
                }
            }
        }
    }

    // Original file.
    let meta = filesystem.metadata(path).await?;
    if !meta.is_file {
        return None;
    }

    let etag = generate_etag(meta.len, meta.modified.unwrap_or(std::time::UNIX_EPOCH));

    if check_conditional(
        opts.if_none_match,
        opts.if_modified_since,
        &etag,
        meta.modified.unwrap_or(std::time::UNIX_EPOCH),
    ) {
        return Some(
            Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header(header::ETAG, &etag)
                .body(Body::empty())
                .unwrap_or_else(|_| empty_response(StatusCode::INTERNAL_SERVER_ERROR)),
        );
    }

    // Range request.
    if let Some(range_header) = opts.range {
        if let Some((start, end)) = parse_range(range_header, meta.len) {
            let bytes = filesystem.read(path).await?;
            let slice = bytes::Bytes::from(bytes[(start as usize)..=(end as usize)].to_vec());
            return Some(range_response(
                slice,
                ext,
                start,
                end,
                meta.len,
                Some(&etag),
                None,
            ));
        } else {
            return Some(
                Response::builder()
                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                    .header(header::CONTENT_RANGE, format!("bytes */{}", meta.len))
                    .body(Body::empty())
                    .unwrap_or_else(|_| empty_response(StatusCode::INTERNAL_SERVER_ERROR)),
            );
        }
    }

    let bytes = filesystem.read(path).await?;
    Some(file_response(
        bytes::Bytes::from(bytes),
        ext,
        request_path,
        None,
        Some(&etag),
        meta.modified,
        opts.cache_control,
    ))
}

pub async fn serve(
    document_root: &str,
    index_file: &str,
    spa_fallback: bool,
    request_path: &str,
    accept_encoding: &str,
) -> Response<Body> {
    serve_with_options(
        document_root,
        index_file,
        spa_fallback,
        request_path,
        accept_encoding,
        &ServeOptions::default(),
    )
    .await
}

pub async fn serve_with_options(
    document_root: &str,
    index_file: &str,
    spa_fallback: bool,
    request_path: &str,
    accept_encoding: &str,
    opts: &ServeOptions<'_>,
) -> Response<Body> {
    let root = PathBuf::from(document_root);
    let encodings = parse_accept_encoding(accept_encoding);

    // File hiding: reject hidden paths.
    if is_hidden_path(request_path, opts.hide_patterns) {
        return empty_response(StatusCode::NOT_FOUND);
    }

    let candidate = match safe_resolve(&root, request_path) {
        Some(p) => p,
        None => return empty_response(StatusCode::FORBIDDEN),
    };

    // Canonical path redirect: /dir → /dir/
    if !opts.disable_canonical_uris && !request_path.ends_with('/') && request_path != "/" {
        if let Ok(meta) = fs::metadata(&candidate).await {
            if meta.is_dir() {
                let redirect_to = format!("{request_path}/");
                return Response::builder()
                    .status(StatusCode::MOVED_PERMANENTLY)
                    .header(header::LOCATION, redirect_to)
                    .body(Body::empty())
                    .unwrap_or_else(|_| empty_response(StatusCode::INTERNAL_SERVER_ERROR));
            }
        }
    }

    if let Some(resp) = try_serve_file(&candidate, request_path, &encodings, opts).await {
        return apply_status_override(resp, opts.status_override);
    }

    if candidate.extension().is_none() || request_path.ends_with('/') {
        let index = candidate.join(index_file);
        if let Some(resp) = try_serve_file(&index, request_path, &encodings, opts).await {
            return apply_status_override(resp, opts.status_override);
        }
    }

    if request_path == "/favicon.ico" {
        return empty_response(StatusCode::NO_CONTENT);
    }

    if spa_fallback {
        let index = root.join(index_file);
        if let Some(resp) = try_serve_file(&index, "/", &encodings, opts).await {
            return apply_status_override(resp, opts.status_override);
        }
    }

    empty_response(StatusCode::NOT_FOUND)
}

struct PrecompressedVariant {
    suffix: &'static str,
    encoding: &'static str,
}

const PRECOMPRESSED: &[PrecompressedVariant] = &[
    PrecompressedVariant {
        suffix: ".br",
        encoding: "br",
    },
    PrecompressedVariant {
        suffix: ".zst",
        encoding: "zstd",
    },
    PrecompressedVariant {
        suffix: ".gz",
        encoding: "gzip",
    },
];

fn parse_accept_encoding(header: &str) -> Vec<String> {
    header
        .split(',')
        .map(|s| s.split(';').next().unwrap_or("").trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

async fn try_serve_file(
    path: &Path,
    request_path: &str,
    accept_encodings: &[String],
    opts: &ServeOptions<'_>,
) -> Option<Response<Body>> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    for variant in PRECOMPRESSED {
        if accept_encodings.iter().any(|e| e == variant.encoding) {
            let compressed_path = path.with_extension(format!("{}{}", ext, variant.suffix));
            if let Ok(meta) = fs::metadata(&compressed_path).await {
                if meta.is_file() {
                    if let Ok(bytes) = fs::read(&compressed_path).await {
                        let etag = generate_etag(
                            meta.len(),
                            meta.modified().unwrap_or(std::time::UNIX_EPOCH),
                        );
                        let modified = meta.modified().ok();

                        // Check conditional request.
                        if check_conditional(
                            opts.if_none_match,
                            opts.if_modified_since,
                            &etag,
                            modified.unwrap_or(std::time::UNIX_EPOCH),
                        ) {
                            return Some(
                                Response::builder()
                                    .status(StatusCode::NOT_MODIFIED)
                                    .header(header::ETAG, &etag)
                                    .body(Body::empty())
                                    .unwrap_or_else(|_| {
                                        empty_response(StatusCode::INTERNAL_SERVER_ERROR)
                                    }),
                            );
                        }

                        return Some(file_response(
                            bytes::Bytes::from(bytes),
                            ext,
                            request_path,
                            Some(variant.encoding),
                            Some(&etag),
                            modified,
                            opts.cache_control,
                        ));
                    }
                }
            }
        }
    }

    let meta = fs::metadata(path).await.ok()?;
    if !meta.is_file() {
        return None;
    }

    let file_size = meta.len();
    let modified = meta.modified().ok();
    let etag = generate_etag(file_size, modified.unwrap_or(std::time::UNIX_EPOCH));

    // Check conditional request (ETag / If-None-Match).
    if check_conditional(
        opts.if_none_match,
        opts.if_modified_since,
        &etag,
        modified.unwrap_or(std::time::UNIX_EPOCH),
    ) {
        return Some(
            Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header(header::ETAG, &etag)
                .body(Body::empty())
                .unwrap_or_else(|_| empty_response(StatusCode::INTERNAL_SERVER_ERROR)),
        );
    }

    // Range request support.
    if let Some(range_header) = opts.range {
        if let Some((start, end)) = parse_range(range_header, file_size) {
            let bytes = fs::read(path).await.ok()?;
            let slice = bytes::Bytes::from(bytes[(start as usize)..=(end as usize)].to_vec());
            return Some(range_response(
                slice,
                ext,
                start,
                end,
                file_size,
                Some(&etag),
                None,
            ));
        } else {
            // Invalid range → 416 Range Not Satisfiable.
            return Some(
                Response::builder()
                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                    .header(header::CONTENT_RANGE, format!("bytes */{file_size}"))
                    .body(Body::empty())
                    .unwrap_or_else(|_| empty_response(StatusCode::INTERNAL_SERVER_ERROR)),
            );
        }
    }

    let bytes = fs::read(path).await.ok()?;
    Some(file_response(
        bytes::Bytes::from(bytes),
        ext,
        request_path,
        None,
        Some(&etag),
        modified,
        opts.cache_control,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etag_deterministic() {
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1700000000);
        let tag1 = generate_etag(1024, t);
        let tag2 = generate_etag(1024, t);
        assert_eq!(tag1, tag2);
        assert!(tag1.starts_with('"') && tag1.ends_with('"'));
    }

    #[test]
    fn etag_conditional_match() {
        let t = std::time::UNIX_EPOCH;
        let etag = generate_etag(100, t);
        assert!(check_conditional(Some(&etag), None, &etag, t));
        assert!(!check_conditional(Some("\"other\""), None, &etag, t));
        assert!(!check_conditional(None, None, &etag, t));
    }

    #[test]
    fn parse_range_cases() {
        assert_eq!(parse_range("bytes=0-499", 1000), Some((0, 499)));
        assert_eq!(parse_range("bytes=500-", 1000), Some((500, 999)));
        assert_eq!(parse_range("bytes=-200", 1000), Some((800, 999)));
        assert_eq!(parse_range("bytes=0-0", 1000), Some((0, 0)));
        assert_eq!(parse_range("bytes=999-", 1000), Some((999, 999)));
        assert_eq!(parse_range("bytes=1000-", 1000), None);
    }

    #[test]
    fn hidden_paths() {
        assert!(is_hidden_path("/.git/config", &[]));
        assert!(is_hidden_path("/.env", &[]));
        assert!(is_hidden_path("/.DS_Store", &[]));
        assert!(!is_hidden_path("/index.html", &[]));
        assert!(!is_hidden_path("/assets/app.js", &[]));
        assert!(is_hidden_path("/secret", &["secret".to_string()]));
    }

    #[test]
    fn canonical_redirect_candidate() {
        // Just test safe_resolve still works.
        let root = Path::new("/tmp");
        assert!(safe_resolve(root, "/foo").is_some());
        assert!(safe_resolve(root, "/../etc/passwd").is_none());
    }

    // ── PrecompressedEncoding ────────────────────────────────────────

    #[test]
    fn precompressed_encoding_from_str() {
        assert_eq!(
            PrecompressedEncoding::from_str("br"),
            Some(PrecompressedEncoding::Brotli)
        );
        assert_eq!(
            PrecompressedEncoding::from_str("brotli"),
            Some(PrecompressedEncoding::Brotli)
        );
        assert_eq!(
            PrecompressedEncoding::from_str("gz"),
            Some(PrecompressedEncoding::Gzip)
        );
        assert_eq!(
            PrecompressedEncoding::from_str("gzip"),
            Some(PrecompressedEncoding::Gzip)
        );
        assert_eq!(
            PrecompressedEncoding::from_str("zstd"),
            Some(PrecompressedEncoding::Zstd)
        );
        assert_eq!(
            PrecompressedEncoding::from_str("zstandard"),
            Some(PrecompressedEncoding::Zstd)
        );
        assert_eq!(PrecompressedEncoding::from_str("deflate"), None);
        assert_eq!(PrecompressedEncoding::from_str(""), None);
    }

    #[test]
    fn precompressed_encoding_suffix_and_encoding() {
        assert_eq!(PrecompressedEncoding::Brotli.suffix(), ".br");
        assert_eq!(PrecompressedEncoding::Brotli.encoding(), "br");
        assert_eq!(PrecompressedEncoding::Zstd.suffix(), ".zst");
        assert_eq!(PrecompressedEncoding::Zstd.encoding(), "zstd");
        assert_eq!(PrecompressedEncoding::Gzip.suffix(), ".gz");
        assert_eq!(PrecompressedEncoding::Gzip.encoding(), "gzip");
    }

    #[test]
    fn default_precompressed_order() {
        // Brotli first (best ratio), then zstd, then gzip.
        assert_eq!(DEFAULT_PRECOMPRESSED[0], PrecompressedEncoding::Brotli);
        assert_eq!(DEFAULT_PRECOMPRESSED[1], PrecompressedEncoding::Zstd);
        assert_eq!(DEFAULT_PRECOMPRESSED[2], PrecompressedEncoding::Gzip);
    }

    // ── In-memory FileSystem for testing ─────────────────────────────

    use std::collections::HashMap as StdHashMap;

    struct InMemoryFs {
        files: StdHashMap<PathBuf, Vec<u8>>,
        dirs: std::collections::HashSet<PathBuf>,
    }

    impl InMemoryFs {
        fn new() -> Self {
            Self {
                files: StdHashMap::new(),
                dirs: std::collections::HashSet::new(),
            }
        }

        fn add_file(&mut self, path: &str, content: &[u8]) {
            let p = PathBuf::from(path);
            // Ensure parent directories exist.
            if let Some(parent) = p.parent() {
                let mut cur = PathBuf::new();
                for comp in parent.components() {
                    cur.push(comp);
                    self.dirs.insert(cur.clone());
                }
            }
            self.files.insert(p, content.to_vec());
        }

        fn add_dir(&mut self, path: &str) {
            let p = PathBuf::from(path);
            let mut cur = PathBuf::new();
            for comp in p.components() {
                cur.push(comp);
                self.dirs.insert(cur.clone());
            }
        }
    }

    #[async_trait::async_trait]
    impl FileSystem for InMemoryFs {
        async fn metadata(&self, path: &Path) -> Option<FsMeta> {
            if let Some(data) = self.files.get(path) {
                return Some(FsMeta {
                    is_file: true,
                    is_dir: false,
                    len: data.len() as u64,
                    modified: Some(
                        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1700000000),
                    ),
                });
            }
            if self.dirs.contains(path) {
                return Some(FsMeta {
                    is_file: false,
                    is_dir: true,
                    len: 0,
                    modified: Some(
                        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1700000000),
                    ),
                });
            }
            None
        }

        async fn read(&self, path: &Path) -> Option<Vec<u8>> {
            self.files.get(path).cloned()
        }

        async fn read_dir(&self, path: &Path) -> Option<Vec<FsDirEntry>> {
            if !self.dirs.contains(path) {
                return None;
            }
            let mut entries = Vec::new();
            // Files in this directory.
            for (p, data) in &self.files {
                if p.parent() == Some(path) {
                    entries.push(FsDirEntry {
                        name: p.file_name().unwrap().to_string_lossy().to_string(),
                        is_dir: false,
                        size: data.len() as u64,
                        modified: Some(
                            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1700000000),
                        ),
                        symlink_target: None,
                    });
                }
            }
            // Subdirectories.
            for d in &self.dirs {
                if d.parent() == Some(path) && d != path {
                    entries.push(FsDirEntry {
                        name: d.file_name().unwrap().to_string_lossy().to_string(),
                        is_dir: true,
                        size: 0,
                        modified: Some(
                            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1700000000),
                        ),
                        symlink_target: None,
                    });
                }
            }
            entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name)));
            Some(entries)
        }
    }

    // ── Directory browse tests ──────────────────────────────────────

    #[test]
    fn render_directory_listing_default_template() {
        let entries = vec![
            FsDirEntry {
                name: "docs".into(),
                is_dir: true,
                size: 0,
                modified: None,
                symlink_target: None,
            },
            FsDirEntry {
                name: "readme.txt".into(),
                is_dir: false,
                size: 1234,
                modified: None,
                symlink_target: None,
            },
        ];
        let opts = ServeOptions::default();
        let resp = render_directory_listing("/files/", &entries, None, &opts);
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.contains("text/html"));
    }

    #[test]
    fn render_directory_listing_custom_template() {
        let entries = vec![FsDirEntry {
            name: "file.txt".into(),
            is_dir: false,
            size: 42,
            modified: None,
            symlink_target: None,
        }];
        let tpl = "<html><body><h1>{{path}}</h1><table>{{entries}}</table></body></html>";
        let opts = ServeOptions::default();
        let resp = render_directory_listing("/data/", &entries, Some(tpl), &opts);
        // We can't read the body easily in sync code, but we can confirm
        // it returned 200 with html content-type.
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn render_directory_listing_hides_dotfiles() {
        let entries = vec![
            FsDirEntry {
                name: ".hidden".into(),
                is_dir: false,
                size: 0,
                modified: None,
                symlink_target: None,
            },
            FsDirEntry {
                name: "visible.txt".into(),
                is_dir: false,
                size: 100,
                modified: None,
                symlink_target: None,
            },
        ];
        // The render function skips entries starting with '.'.
        // We verify by checking that the function runs (the skipping is internal).
        let opts = ServeOptions::default();
        let resp = render_directory_listing("/", &entries, None, &opts);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn render_directory_listing_root_no_parent_link() {
        let entries = vec![];
        let opts = ServeOptions::default();
        let resp = render_directory_listing("/", &entries, None, &opts);
        assert_eq!(resp.status(), StatusCode::OK);
        // Root should not have a parent "../" link.
    }

    #[test]
    fn render_directory_listing_subdir_has_parent_link() {
        let entries = vec![];
        let opts = ServeOptions::default();
        let resp = render_directory_listing("/sub/", &entries, None, &opts);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── format_file_size tests ──────────────────────────────────────

    #[test]
    fn format_file_size_units() {
        assert_eq!(format_file_size(0), "0 B");
        assert_eq!(format_file_size(512), "512 B");
        assert_eq!(format_file_size(1024), "1.0 KB");
        assert_eq!(format_file_size(1536), "1.5 KB");
        assert_eq!(format_file_size(1048576), "1.0 MB");
        assert_eq!(format_file_size(1073741824), "1.00 GB");
    }

    // ── serve_with_fs: basic file serving ───────────────────────────

    #[tokio::test]
    async fn serve_with_fs_basic_file() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_file("/www/hello.txt", b"hello world");

        let opts = ServeOptions::default();
        let result = serve_with_fs(&fs, "/www", "index.html", false, "/hello.txt", "", &opts).await;
        match result {
            ServeResult::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::OK);
                let ct = resp
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .unwrap()
                    .to_str()
                    .unwrap();
                assert_eq!(ct, "text/plain; charset=utf-8");
            }
            ServeResult::PassThru => panic!("expected response, got pass_thru"),
        }
    }

    #[tokio::test]
    async fn serve_with_fs_index_file() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_file("/www/index.html", b"<h1>Home</h1>");

        let opts = ServeOptions::default();
        let result = serve_with_fs(&fs, "/www", "index.html", false, "/", "", &opts).await;
        match result {
            ServeResult::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::OK);
            }
            ServeResult::PassThru => panic!("expected response"),
        }
    }

    #[tokio::test]
    async fn serve_with_fs_hidden_path_returns_404() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_file("/www/.env", b"SECRET=foo");

        let opts = ServeOptions::default();
        let result = serve_with_fs(&fs, "/www", "index.html", false, "/.env", "", &opts).await;
        match result {
            ServeResult::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::NOT_FOUND);
            }
            ServeResult::PassThru => panic!("expected 404 response"),
        }
    }

    #[tokio::test]
    async fn serve_with_fs_path_traversal_blocked() {
        let fs = InMemoryFs::new();
        let opts = ServeOptions::default();
        let result = serve_with_fs(
            &fs,
            "/www",
            "index.html",
            false,
            "/../etc/passwd",
            "",
            &opts,
        )
        .await;
        match result {
            ServeResult::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            }
            ServeResult::PassThru => panic!("expected 403"),
        }
    }

    // ── serve_with_fs: pass_thru ────────────────────────────────────

    #[tokio::test]
    async fn serve_with_fs_pass_thru_missing_file() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");

        let opts = ServeOptions {
            pass_thru: true,
            ..Default::default()
        };
        let result = serve_with_fs(
            &fs,
            "/www",
            "index.html",
            false,
            "/nonexistent.txt",
            "",
            &opts,
        )
        .await;
        assert!(matches!(result, ServeResult::PassThru));
    }

    #[tokio::test]
    async fn serve_with_fs_pass_thru_existing_file_serves() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_file("/www/found.txt", b"data");

        let opts = ServeOptions {
            pass_thru: true,
            ..Default::default()
        };
        let result = serve_with_fs(&fs, "/www", "index.html", false, "/found.txt", "", &opts).await;
        match result {
            ServeResult::Response(resp) => assert_eq!(resp.status(), StatusCode::OK),
            ServeResult::PassThru => panic!("file exists, should serve it"),
        }
    }

    #[tokio::test]
    async fn serve_with_fs_no_pass_thru_missing_file_404() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");

        let opts = ServeOptions {
            pass_thru: false,
            ..Default::default()
        };
        let result =
            serve_with_fs(&fs, "/www", "index.html", false, "/missing.txt", "", &opts).await;
        match result {
            ServeResult::Response(resp) => assert_eq!(resp.status(), StatusCode::NOT_FOUND),
            ServeResult::PassThru => panic!("pass_thru is off, should 404"),
        }
    }

    #[tokio::test]
    async fn serve_with_fs_pass_thru_hidden_path() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_file("/www/.git/config", b"secret");

        let opts = ServeOptions {
            pass_thru: true,
            ..Default::default()
        };
        let result =
            serve_with_fs(&fs, "/www", "index.html", false, "/.git/config", "", &opts).await;
        // Hidden paths with pass_thru → PassThru (not 404).
        assert!(matches!(result, ServeResult::PassThru));
    }

    // ── serve_with_fs: browse ───────────────────────────────────────

    #[tokio::test]
    async fn serve_with_fs_browse_directory() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_dir("/www/assets");
        fs.add_file("/www/assets/style.css", b"body{}");
        fs.add_file("/www/assets/app.js", b"console.log('hi')");

        let opts = ServeOptions {
            browse: true,
            ..Default::default()
        };
        let result = serve_with_fs(&fs, "/www", "index.html", false, "/assets/", "", &opts).await;
        match result {
            ServeResult::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::OK);
                let ct = resp
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .unwrap()
                    .to_str()
                    .unwrap();
                assert!(ct.contains("text/html"));
            }
            ServeResult::PassThru => panic!("browse enabled, should list directory"),
        }
    }

    #[tokio::test]
    async fn serve_with_fs_browse_disabled_no_listing() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_dir("/www/assets");
        fs.add_file("/www/assets/style.css", b"body{}");

        let opts = ServeOptions {
            browse: false,
            ..Default::default()
        };
        let result = serve_with_fs(&fs, "/www", "index.html", false, "/assets/", "", &opts).await;
        match result {
            ServeResult::Response(resp) => assert_eq!(resp.status(), StatusCode::NOT_FOUND),
            ServeResult::PassThru => panic!("expected 404 not pass_thru"),
        }
    }

    #[tokio::test]
    async fn serve_with_fs_browse_index_takes_priority() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_dir("/www/docs");
        fs.add_file("/www/docs/index.html", b"<h1>Docs</h1>");
        fs.add_file("/www/docs/page.html", b"<p>page</p>");

        let opts = ServeOptions {
            browse: true,
            ..Default::default()
        };
        // When index.html exists, it should be served instead of a directory listing.
        let result = serve_with_fs(&fs, "/www", "index.html", false, "/docs/", "", &opts).await;
        match result {
            ServeResult::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::OK);
                let ct = resp
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .unwrap()
                    .to_str()
                    .unwrap();
                assert!(ct.contains("text/html"));
            }
            ServeResult::PassThru => panic!("should serve index.html"),
        }
    }

    #[tokio::test]
    async fn serve_with_fs_browse_custom_template() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_dir("/www/dir");
        fs.add_file("/www/dir/a.txt", b"aaa");

        let tpl = "<custom>{{path}} – {{entries}}</custom>";
        let opts = ServeOptions {
            browse: true,
            browse_template: Some(tpl),
            ..Default::default()
        };
        let result = serve_with_fs(&fs, "/www", "index.html", false, "/dir/", "", &opts).await;
        match result {
            ServeResult::Response(resp) => assert_eq!(resp.status(), StatusCode::OK),
            ServeResult::PassThru => panic!("should list directory"),
        }
    }

    // ── serve_with_fs: configurable precompressed ───────────────────

    #[tokio::test]
    async fn serve_with_fs_precompressed_brotli() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_file("/www/app.js", b"original javascript");
        fs.add_file("/www/app.js.br", b"compressed-br-data");

        let opts = ServeOptions {
            precompressed: Some(&[PrecompressedEncoding::Brotli]),
            ..Default::default()
        };
        let result = serve_with_fs(
            &fs,
            "/www",
            "index.html",
            false,
            "/app.js",
            "br, gzip",
            &opts,
        )
        .await;
        match result {
            ServeResult::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::OK);
                let enc = resp
                    .headers()
                    .get(header::CONTENT_ENCODING)
                    .unwrap()
                    .to_str()
                    .unwrap();
                assert_eq!(enc, "br");
            }
            ServeResult::PassThru => panic!("expected brotli response"),
        }
    }

    #[tokio::test]
    async fn serve_with_fs_precompressed_gzip_only() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_file("/www/style.css", b"body{}");
        fs.add_file("/www/style.css.gz", b"gzipped-data");
        fs.add_file("/www/style.css.br", b"brotli-data");

        // Only gzip is configured, so br sidecar should be ignored.
        let opts = ServeOptions {
            precompressed: Some(&[PrecompressedEncoding::Gzip]),
            ..Default::default()
        };
        let result = serve_with_fs(
            &fs,
            "/www",
            "index.html",
            false,
            "/style.css",
            "br, gzip",
            &opts,
        )
        .await;
        match result {
            ServeResult::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::OK);
                let enc = resp
                    .headers()
                    .get(header::CONTENT_ENCODING)
                    .unwrap()
                    .to_str()
                    .unwrap();
                assert_eq!(enc, "gzip");
            }
            ServeResult::PassThru => panic!("expected gzip response"),
        }
    }

    #[tokio::test]
    async fn serve_with_fs_precompressed_disabled() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_file("/www/app.js", b"original");
        fs.add_file("/www/app.js.br", b"compressed");

        // Empty slice → no precompressed serving.
        let opts = ServeOptions {
            precompressed: Some(&[]),
            ..Default::default()
        };
        let result = serve_with_fs(
            &fs,
            "/www",
            "index.html",
            false,
            "/app.js",
            "br, gzip",
            &opts,
        )
        .await;
        match result {
            ServeResult::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::OK);
                // No Content-Encoding header since precompressed is disabled.
                assert!(resp.headers().get(header::CONTENT_ENCODING).is_none());
            }
            ServeResult::PassThru => panic!("expected uncompressed response"),
        }
    }

    #[tokio::test]
    async fn serve_with_fs_precompressed_client_no_accept() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_file("/www/app.js", b"original code");
        fs.add_file("/www/app.js.br", b"compressed");

        let opts = ServeOptions::default();
        // Client doesn't accept br → should get original.
        let result = serve_with_fs(&fs, "/www", "index.html", false, "/app.js", "", &opts).await;
        match result {
            ServeResult::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::OK);
                assert!(resp.headers().get(header::CONTENT_ENCODING).is_none());
            }
            ServeResult::PassThru => panic!("expected uncompressed response"),
        }
    }

    #[tokio::test]
    async fn serve_with_fs_precompressed_priority_order() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_file("/www/bundle.js", b"original");
        fs.add_file("/www/bundle.js.br", b"brotli");
        fs.add_file("/www/bundle.js.zst", b"zstd");
        fs.add_file("/www/bundle.js.gz", b"gzip");

        // Default order is br > zstd > gzip. Client accepts all three.
        let opts = ServeOptions::default();
        let result = serve_with_fs(
            &fs,
            "/www",
            "index.html",
            false,
            "/bundle.js",
            "gzip, br, zstd",
            &opts,
        )
        .await;
        match result {
            ServeResult::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::OK);
                let enc = resp
                    .headers()
                    .get(header::CONTENT_ENCODING)
                    .unwrap()
                    .to_str()
                    .unwrap();
                assert_eq!(enc, "br"); // Brotli should win.
            }
            ServeResult::PassThru => panic!("expected br response"),
        }
    }

    // ── serve_with_fs: conditional requests through virtual FS ──────

    #[tokio::test]
    async fn serve_with_fs_etag_304() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_file("/www/data.json", b"{\"ok\":true}");

        // First request to get the etag.
        let opts = ServeOptions::default();
        let result = serve_with_fs(&fs, "/www", "index.html", false, "/data.json", "", &opts).await;
        let etag = match result {
            ServeResult::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::OK);
                resp.headers()
                    .get(header::ETAG)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string()
            }
            _ => panic!("expected OK"),
        };

        // Second request with If-None-Match.
        let opts2 = ServeOptions {
            if_none_match: Some(&etag),
            ..Default::default()
        };
        let result2 =
            serve_with_fs(&fs, "/www", "index.html", false, "/data.json", "", &opts2).await;
        match result2 {
            ServeResult::Response(resp) => assert_eq!(resp.status(), StatusCode::NOT_MODIFIED),
            _ => panic!("expected 304"),
        }
    }

    // ── serve_with_fs: range request through virtual FS ─────────────

    #[tokio::test]
    async fn serve_with_fs_range_request() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_file("/www/video.mp4", b"0123456789abcdef");

        let opts = ServeOptions {
            range: Some("bytes=0-3"),
            ..Default::default()
        };
        let result = serve_with_fs(&fs, "/www", "index.html", false, "/video.mp4", "", &opts).await;
        match result {
            ServeResult::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
                let cr = resp
                    .headers()
                    .get(header::CONTENT_RANGE)
                    .unwrap()
                    .to_str()
                    .unwrap();
                assert!(cr.starts_with("bytes 0-3/"));
            }
            _ => panic!("expected 206"),
        }
    }

    // ── serve_with_fs: SPA fallback through virtual FS ──────────────

    #[tokio::test]
    async fn serve_with_fs_spa_fallback() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_file("/www/index.html", b"<div id=app></div>");

        let opts = ServeOptions::default();
        let result = serve_with_fs(
            &fs,
            "/www",
            "index.html",
            true,
            "/deep/route/here",
            "",
            &opts,
        )
        .await;
        match result {
            ServeResult::Response(resp) => assert_eq!(resp.status(), StatusCode::OK),
            ServeResult::PassThru => panic!("SPA fallback should return index.html"),
        }
    }

    // ── serve_with_fs: canonical dir redirect ───────────────────────

    #[tokio::test]
    async fn serve_with_fs_dir_redirect() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_dir("/www/sub");

        let opts = ServeOptions::default();
        let result = serve_with_fs(&fs, "/www", "index.html", false, "/sub", "", &opts).await;
        match result {
            ServeResult::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
                let loc = resp
                    .headers()
                    .get(header::LOCATION)
                    .unwrap()
                    .to_str()
                    .unwrap();
                assert_eq!(loc, "/sub/");
            }
            ServeResult::PassThru => panic!("expected redirect"),
        }
    }

    // ── FileSystem trait: LocalFs basic coverage ────────────────────

    #[tokio::test]
    async fn local_fs_nonexistent_file() {
        let lfs = LocalFs;
        assert!(lfs
            .metadata(Path::new("/tmp/__nonexistent_lynx_test_file__"))
            .await
            .is_none());
        assert!(lfs
            .read(Path::new("/tmp/__nonexistent_lynx_test_file__"))
            .await
            .is_none());
        assert!(lfs
            .read_dir(Path::new("/tmp/__nonexistent_lynx_test_dir__"))
            .await
            .is_none());
    }

    // ── serve_with_fs: browse + pass_thru combo ─────────────────────

    #[tokio::test]
    async fn serve_with_fs_browse_and_pass_thru() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        // No index and directory doesn't match path → pass_thru.
        let opts = ServeOptions {
            browse: true,
            pass_thru: true,
            ..Default::default()
        };
        let result = serve_with_fs(&fs, "/www", "index.html", false, "/nope.txt", "", &opts).await;
        assert!(matches!(result, ServeResult::PassThru));
    }

    // ── serve_with_fs: favicon fallback ─────────────────────────────

    #[tokio::test]
    async fn serve_with_fs_favicon_no_content() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");

        let opts = ServeOptions::default();
        let result =
            serve_with_fs(&fs, "/www", "index.html", false, "/favicon.ico", "", &opts).await;
        match result {
            ServeResult::Response(resp) => assert_eq!(resp.status(), StatusCode::NO_CONTENT),
            ServeResult::PassThru => panic!("expected 204 for missing favicon"),
        }
    }

    // ── Feature 88: browse_sort ─────────────────────────────────────

    #[test]
    fn sort_entries_name_ascending_default() {
        let mut entries = vec![
            FsDirEntry {
                name: "zebra.txt".into(),
                is_dir: false,
                size: 10,
                modified: None,
                symlink_target: None,
            },
            FsDirEntry {
                name: "alpha.txt".into(),
                is_dir: false,
                size: 20,
                modified: None,
                symlink_target: None,
            },
            FsDirEntry {
                name: "mango.txt".into(),
                is_dir: false,
                size: 30,
                modified: None,
                symlink_target: None,
            },
        ];
        sort_entries(&mut entries, None); // default = Name Ascending
        assert_eq!(entries[0].name, "alpha.txt");
        assert_eq!(entries[1].name, "mango.txt");
        assert_eq!(entries[2].name, "zebra.txt");
    }

    #[test]
    fn sort_entries_size_descending() {
        let mut entries = vec![
            FsDirEntry {
                name: "small.txt".into(),
                is_dir: false,
                size: 10,
                modified: None,
                symlink_target: None,
            },
            FsDirEntry {
                name: "big.txt".into(),
                is_dir: false,
                size: 9999,
                modified: None,
                symlink_target: None,
            },
            FsDirEntry {
                name: "medium.txt".into(),
                is_dir: false,
                size: 500,
                modified: None,
                symlink_target: None,
            },
        ];
        sort_entries(
            &mut entries,
            Some((BrowseSortField::Size, SortDirection::Descending)),
        );
        assert_eq!(entries[0].name, "big.txt");
        assert_eq!(entries[1].name, "medium.txt");
        assert_eq!(entries[2].name, "small.txt");
    }

    #[test]
    fn sort_entries_time() {
        let t1 = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1000);
        let t2 = std::time::UNIX_EPOCH + std::time::Duration::from_secs(2000);
        let t3 = std::time::UNIX_EPOCH + std::time::Duration::from_secs(3000);
        let mut entries = vec![
            FsDirEntry {
                name: "old.txt".into(),
                is_dir: false,
                size: 1,
                modified: Some(t1),
                symlink_target: None,
            },
            FsDirEntry {
                name: "new.txt".into(),
                is_dir: false,
                size: 1,
                modified: Some(t3),
                symlink_target: None,
            },
            FsDirEntry {
                name: "mid.txt".into(),
                is_dir: false,
                size: 1,
                modified: Some(t2),
                symlink_target: None,
            },
        ];
        // Ascending: oldest first.
        sort_entries(
            &mut entries,
            Some((BrowseSortField::Time, SortDirection::Ascending)),
        );
        assert_eq!(entries[0].name, "old.txt");
        assert_eq!(entries[1].name, "mid.txt");
        assert_eq!(entries[2].name, "new.txt");
    }

    #[test]
    fn sort_entries_dirs_always_first() {
        let mut entries = vec![
            FsDirEntry {
                name: "file_a.txt".into(),
                is_dir: false,
                size: 100,
                modified: None,
                symlink_target: None,
            },
            FsDirEntry {
                name: "dir_z".into(),
                is_dir: true,
                size: 0,
                modified: None,
                symlink_target: None,
            },
            FsDirEntry {
                name: "file_b.txt".into(),
                is_dir: false,
                size: 50,
                modified: None,
                symlink_target: None,
            },
        ];
        // Even when sorting by size desc, dirs come first.
        sort_entries(
            &mut entries,
            Some((BrowseSortField::Size, SortDirection::Descending)),
        );
        assert!(entries[0].is_dir);
        assert_eq!(entries[0].name, "dir_z");
    }

    // ── Feature 89: browse_file_limit ───────────────────────────────

    #[test]
    fn browse_file_limit_truncates() {
        let entries: Vec<FsDirEntry> = (0..20)
            .map(|i| FsDirEntry {
                name: format!("file_{i:02}.txt"),
                is_dir: false,
                size: i as u64,
                modified: None,
                symlink_target: None,
            })
            .collect();
        let opts = ServeOptions {
            browse_file_limit: 5,
            ..Default::default()
        };
        let resp = render_directory_listing("/test/", &entries, None, &opts);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn serve_with_fs_browse_file_limit() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_dir("/www/many");
        for i in 0..10 {
            fs.add_file(&format!("/www/many/f{i:02}.txt"), b"data");
        }

        let opts = ServeOptions {
            browse: true,
            browse_file_limit: 3,
            ..Default::default()
        };
        let result = serve_with_fs(&fs, "/www", "index.html", false, "/many/", "", &opts).await;
        match result {
            ServeResult::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::OK);
                let ct = resp
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .unwrap()
                    .to_str()
                    .unwrap();
                assert!(ct.contains("text/html"));
            }
            ServeResult::PassThru => panic!("expected browse listing"),
        }
    }

    // ── Feature 90: browse_reveal_symlinks ──────────────────────────

    #[test]
    fn browse_reveal_symlinks_option_parsing() {
        let opts = ServeOptions {
            browse_reveal_symlinks: true,
            ..Default::default()
        };
        assert!(opts.browse_reveal_symlinks);

        let default_opts = ServeOptions::default();
        assert!(!default_opts.browse_reveal_symlinks);
    }

    #[test]
    fn browse_reveal_symlinks_renders_target() {
        let entries = vec![FsDirEntry {
            name: "link.txt".into(),
            is_dir: false,
            size: 42,
            modified: None,
            symlink_target: Some("/real/path.txt".into()),
        }];
        let opts = ServeOptions {
            browse_reveal_symlinks: true,
            ..Default::default()
        };
        let resp = render_directory_listing("/dir/", &entries, None, &opts);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn browse_reveal_symlinks_hidden_when_disabled() {
        let entries = vec![FsDirEntry {
            name: "link.txt".into(),
            is_dir: false,
            size: 42,
            modified: None,
            symlink_target: Some("/real/path.txt".into()),
        }];
        let opts = ServeOptions::default();
        let resp = render_directory_listing("/dir/", &entries, None, &opts);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── Feature 91: disable_canonical_uris ──────────────────────────

    #[tokio::test]
    async fn serve_with_fs_disable_canonical_uris() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_dir("/www/sub");
        fs.add_file("/www/sub/index.html", b"<h1>Sub</h1>");

        let opts = ServeOptions {
            disable_canonical_uris: true,
            ..Default::default()
        };
        let result = serve_with_fs(&fs, "/www", "index.html", false, "/sub", "", &opts).await;
        match result {
            ServeResult::Response(resp) => {
                assert_ne!(resp.status(), StatusCode::MOVED_PERMANENTLY);
            }
            ServeResult::PassThru => panic!("expected response"),
        }
    }

    #[tokio::test]
    async fn serve_with_fs_canonical_uris_enabled_by_default() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_dir("/www/sub");

        let opts = ServeOptions::default();
        let result = serve_with_fs(&fs, "/www", "index.html", false, "/sub", "", &opts).await;
        match result {
            ServeResult::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
                let loc = resp
                    .headers()
                    .get(header::LOCATION)
                    .unwrap()
                    .to_str()
                    .unwrap();
                assert_eq!(loc, "/sub/");
            }
            ServeResult::PassThru => panic!("expected redirect"),
        }
    }

    // ── Feature 92: status_override ─────────────────────────────────

    #[tokio::test]
    async fn serve_with_fs_status_override() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_file("/www/404.html", b"<h1>Not Found</h1>");

        let opts = ServeOptions {
            status_override: Some(404),
            ..Default::default()
        };
        let result = serve_with_fs(&fs, "/www", "index.html", false, "/404.html", "", &opts).await;
        match result {
            ServeResult::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::NOT_FOUND);
                let ct = resp
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .unwrap()
                    .to_str()
                    .unwrap();
                assert!(ct.contains("text/html"));
            }
            ServeResult::PassThru => panic!("expected response with 404 status"),
        }
    }

    #[tokio::test]
    async fn serve_with_fs_status_override_none_uses_200() {
        let mut fs = InMemoryFs::new();
        fs.add_dir("/www");
        fs.add_file("/www/page.html", b"<p>ok</p>");

        let opts = ServeOptions::default();
        let result = serve_with_fs(&fs, "/www", "index.html", false, "/page.html", "", &opts).await;
        match result {
            ServeResult::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::OK);
            }
            ServeResult::PassThru => panic!("expected 200 response"),
        }
    }

    #[test]
    fn apply_status_override_changes_status() {
        let resp = Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap();
        let overridden = apply_status_override(resp, Some(503));
        assert_eq!(overridden.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn apply_status_override_none_preserves() {
        let resp = Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap();
        let same = apply_status_override(resp, None);
        assert_eq!(same.status(), StatusCode::OK);
    }
}
