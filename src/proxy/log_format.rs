//! NGINX-style configurable access log format templates.
//!
//! # Architecture
//!
//! ```text
//! Log Format Engine
//! ├── LogVariable enum       — All supported $variables ($remote_addr, $status, ...)
//! ├── LogToken enum           — Literal(String) | Variable(LogVariable)
//! ├── LogTemplate struct      — Parsed template (name + Vec<LogToken>)
//! ├── LogContext struct       — Per-request fields for rendering
//! ├── LogFormatPreset enum    — Combined / Common / Json / Custom (AtomicU8)
//! ├── parse_log_format()      — NGINX-style format string parser
//! └── LogFormatMetrics        — lines_rendered / render_errors counters
//! ```
//!
//! # Why
//!
//! NGINX's `log_format` directive lets operators define custom access log
//! formats with variables like `$remote_addr`, `$request`, `$status`,
//! `$body_bytes_sent`. Having the same flexibility in Lynxx means operators
//! can match their existing log pipelines (ELK, Splunk, Datadog) without
//! post-processing, and switch between structured JSON and human-readable
//! combined formats at runtime.
//!
//! # Preset formats
//!
//! | Preset    | Description                                      |
//! |-----------|--------------------------------------------------|
//! | Combined  | NGINX combined (default) — CLF + referer + UA    |
//! | Common    | Common Log Format (CLF)                          |
//! | Json      | Structured JSON with all fields                  |
//! | Custom    | User-defined template string                     |

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::time::Duration;

// ═══════════════════════════════════════════════════════════════════════════
// Global statics — lock-free runtime configuration
// ═══════════════════════════════════════════════════════════════════════════

/// Master kill-switch for access log formatting. When false, log rendering
/// is skipped entirely (callers should check before allocating a LogContext).
static LOG_FORMAT_ENABLED: AtomicBool = AtomicBool::new(true);

/// Enable or disable log format rendering globally.
pub fn set_log_format_enabled(enabled: bool) {
    LOG_FORMAT_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Check if log format rendering is globally enabled.
pub fn is_log_format_enabled() -> bool {
    LOG_FORMAT_ENABLED.load(Ordering::Relaxed)
}

// ═══════════════════════════════════════════════════════════════════════════
// LogFormatPreset — atomic preset selector
// ═══════════════════════════════════════════════════════════════════════════

/// Active log format preset. Stored as `AtomicU8` for lock-free switching.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LogFormatPreset {
    /// NGINX combined format: CLF + referer + user agent. Default.
    Combined = 0,
    /// Common Log Format (CLF): remote_addr, consumer, time, request, status, bytes.
    Common = 1,
    /// Structured JSON with all available fields.
    Json = 2,
    /// User-supplied custom template string.
    Custom = 3,
}

impl LogFormatPreset {
    /// Convert from raw `u8`, defaulting to `Combined` for unknown values.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Combined,
            1 => Self::Common,
            2 => Self::Json,
            3 => Self::Custom,
            _ => Self::Combined,
        }
    }

    /// Convert to `u8` for atomic storage.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Global preset selector, atomically switchable at runtime.
static ACTIVE_PRESET: AtomicU8 = AtomicU8::new(LogFormatPreset::Combined as u8);

/// Set the active log format preset.
pub fn set_active_preset(preset: LogFormatPreset) {
    ACTIVE_PRESET.store(preset.as_u8(), Ordering::Relaxed);
}

/// Get the currently active log format preset.
pub fn active_preset() -> LogFormatPreset {
    LogFormatPreset::from_u8(ACTIVE_PRESET.load(Ordering::Relaxed))
}

// ═══════════════════════════════════════════════════════════════════════════
// LogVariable — all supported template variables
// ═══════════════════════════════════════════════════════════════════════════

/// Supported log format variables, mirroring NGINX variable names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogVariable {
    /// Client IP address (`$remote_addr`).
    RemoteAddr,
    /// Client port (`$remote_port`).
    RemotePort,
    /// Local time in Common Log Format (`$time_local`).
    TimeLocal,
    /// ISO 8601 timestamp (`$time_iso8601`).
    TimeIso8601,
    /// Full request line: method + URI + protocol (`$request`).
    Request,
    /// HTTP response status code (`$status`).
    Status,
    /// Bytes sent in response body, excluding headers (`$body_bytes_sent`).
    BodyBytesSent,
    /// Total bytes sent including headers (`$bytes_sent`).
    BytesSent,
    /// HTTP Referer header (`$http_referer`).
    HttpReferer,
    /// HTTP User-Agent header (`$http_user_agent`).
    HttpUserAgent,
    /// Request processing time in seconds with millisecond precision (`$request_time`).
    RequestTime,
    /// Upstream server address (`$upstream_addr`).
    UpstreamAddr,
    /// Upstream response status code (`$upstream_status`).
    UpstreamStatus,
    /// Upstream response time in seconds (`$upstream_response_time`).
    UpstreamResponseTime,
    /// Total request length including headers and body (`$request_length`).
    RequestLength,
    /// Connection serial number (`$connection`).
    Connection,
    /// Number of requests on this connection (`$connection_requests`).
    ConnectionRequests,
    /// Request scheme: http or https (`$scheme`).
    Scheme,
    /// Host header value (`$host`).
    Host,
    /// Request URI (`$uri`).
    Uri,
    /// HTTP method (`$method`).
    Method,
    /// HTTP protocol version (`$protocol`).
    Protocol,
    /// Matched service name (`$service_name`).
    ServiceName,
    /// Matched service ID (`$service_id`).
    ServiceId,
    /// Matched route ID (`$route_id`).
    RouteId,
    /// Authenticated consumer username (`$consumer_username`).
    ConsumerUsername,
    /// Unique request identifier (`$request_id`).
    RequestId,
}

impl LogVariable {
    /// Parse a variable name (without the `$` prefix) into a `LogVariable`.
    pub fn from_str(name: &str) -> Option<Self> {
        match name {
            "remote_addr" => Some(Self::RemoteAddr),
            "remote_port" => Some(Self::RemotePort),
            "time_local" => Some(Self::TimeLocal),
            "time_iso8601" => Some(Self::TimeIso8601),
            "request" => Some(Self::Request),
            "status" => Some(Self::Status),
            "body_bytes_sent" => Some(Self::BodyBytesSent),
            "bytes_sent" => Some(Self::BytesSent),
            "http_referer" => Some(Self::HttpReferer),
            "http_user_agent" => Some(Self::HttpUserAgent),
            "request_time" => Some(Self::RequestTime),
            "upstream_addr" => Some(Self::UpstreamAddr),
            "upstream_status" => Some(Self::UpstreamStatus),
            "upstream_response_time" => Some(Self::UpstreamResponseTime),
            "request_length" => Some(Self::RequestLength),
            "connection" => Some(Self::Connection),
            "connection_requests" => Some(Self::ConnectionRequests),
            "scheme" => Some(Self::Scheme),
            "host" => Some(Self::Host),
            "uri" => Some(Self::Uri),
            "method" => Some(Self::Method),
            "protocol" => Some(Self::Protocol),
            "service_name" => Some(Self::ServiceName),
            "service_id" => Some(Self::ServiceId),
            "route_id" => Some(Self::RouteId),
            "consumer_username" => Some(Self::ConsumerUsername),
            "request_id" => Some(Self::RequestId),
            _ => None,
        }
    }

    /// Return the canonical variable name (without `$` prefix).
    pub fn name(&self) -> &'static str {
        match self {
            Self::RemoteAddr => "remote_addr",
            Self::RemotePort => "remote_port",
            Self::TimeLocal => "time_local",
            Self::TimeIso8601 => "time_iso8601",
            Self::Request => "request",
            Self::Status => "status",
            Self::BodyBytesSent => "body_bytes_sent",
            Self::BytesSent => "bytes_sent",
            Self::HttpReferer => "http_referer",
            Self::HttpUserAgent => "http_user_agent",
            Self::RequestTime => "request_time",
            Self::UpstreamAddr => "upstream_addr",
            Self::UpstreamStatus => "upstream_status",
            Self::UpstreamResponseTime => "upstream_response_time",
            Self::RequestLength => "request_length",
            Self::Connection => "connection",
            Self::ConnectionRequests => "connection_requests",
            Self::Scheme => "scheme",
            Self::Host => "host",
            Self::Uri => "uri",
            Self::Method => "method",
            Self::Protocol => "protocol",
            Self::ServiceName => "service_name",
            Self::ServiceId => "service_id",
            Self::RouteId => "route_id",
            Self::ConsumerUsername => "consumer_username",
            Self::RequestId => "request_id",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// LogToken + LogTemplate — parsed format representation
// ═══════════════════════════════════════════════════════════════════════════

/// A single token in a parsed log format template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogToken {
    /// Literal text (whitespace, brackets, quotes, etc.).
    Literal(String),
    /// A variable reference to be substituted at render time.
    Variable(LogVariable),
}

/// How resolved variable values are escaped when a template is rendered.
///
/// Resolved values are attacker-influenced (they come from request headers,
/// the URI, etc.), so they must never be emitted verbatim into a log line:
/// in text formats a raw `\n` forges a fake log record (CWE-117), and in the
/// JSON format a raw `"` terminates the surrounding string literal and lets a
/// caller inject forged top-level keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ValueEscape {
    /// NGINX-style access-log escaping for human-readable formats: C0 control
    /// characters (and DEL) are rendered as `\xNN` so a value can never break
    /// out onto a new physical line. Used by Combined / Common / Custom.
    Text,
    /// Full JSON string-content escaping for the structured JSON preset, so the
    /// rendered line is always valid JSON and values cannot inject extra keys.
    Json,
}

/// A parsed log format template, ready for repeated rendering.
#[derive(Clone, Debug)]
pub struct LogTemplate {
    /// Ordered list of tokens comprising the format.
    pub tokens: Vec<LogToken>,
    /// Human-readable name for this template (e.g. "combined", "custom_v2").
    pub name: String,
    /// How resolved values are escaped at render time. Defaults to `Text`
    /// (NGINX-style) for custom templates; set to `Json` for the JSON preset
    /// so the output stays valid JSON. Private so the only way to obtain a
    /// template is through `parse_log_format` / `render_preset`, which set it.
    escape: ValueEscape,
}

// ═══════════════════════════════════════════════════════════════════════════
// LogFormatError — parser errors
// ═══════════════════════════════════════════════════════════════════════════

/// Errors that can occur while parsing a log format string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogFormatError {
    /// A `$variable_name` was not recognized.
    UnknownVariable(String),
    /// A backslash escape was started but the string ended before the
    /// escaped character.
    UnclosedEscape,
}

impl std::fmt::Display for LogFormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownVariable(name) => write!(f, "unknown log variable: ${}", name),
            Self::UnclosedEscape => write!(f, "unclosed escape sequence at end of format string"),
        }
    }
}

impl std::error::Error for LogFormatError {}

// ═══════════════════════════════════════════════════════════════════════════
// Preset format strings
// ═══════════════════════════════════════════════════════════════════════════

/// NGINX combined log format: CLF + referer + user agent.
pub const COMBINED_FORMAT: &str = "$remote_addr - $consumer_username [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"";

/// Common Log Format (CLF).
pub const COMMON_FORMAT: &str =
    "$remote_addr - $consumer_username [$time_local] \"$request\" $status $body_bytes_sent";

/// Structured JSON format with all fields.
pub const JSON_FORMAT: &str = r#"{"remote_addr":"$remote_addr","remote_port":"$remote_port","time":"$time_iso8601","method":"$method","uri":"$uri","protocol":"$protocol","status":"$status","body_bytes_sent":"$body_bytes_sent","bytes_sent":"$bytes_sent","http_referer":"$http_referer","http_user_agent":"$http_user_agent","request_time":"$request_time","upstream_addr":"$upstream_addr","upstream_status":"$upstream_status","upstream_response_time":"$upstream_response_time","request_length":"$request_length","scheme":"$scheme","host":"$host","service_name":"$service_name","service_id":"$service_id","route_id":"$route_id","consumer_username":"$consumer_username","request_id":"$request_id"}"#;

// ═══════════════════════════════════════════════════════════════════════════
// Parser — NGINX-style format string → LogTemplate
// ═══════════════════════════════════════════════════════════════════════════

/// Parse an NGINX-style log format string into a `LogTemplate`.
///
/// Variables start with `$` and end at the first character that is not an
/// ASCII alphanumeric or underscore. Literal text is everything else.
/// Backslash escapes are supported: `\"` produces a literal `"`.
///
/// A bare `$` (one not followed by a valid variable name) is treated as a
/// literal `$`, matching NGINX, which only substitutes recognized variable
/// names and otherwise leaves the `$` in place. A `$` followed by name-like
/// characters that don't form a known variable is likewise re-emitted
/// verbatim rather than producing an error.
///
/// # Errors
///
/// Returns `LogFormatError::UnclosedEscape` if the string ends with a lone
/// `\`. (Unknown `$name` sequences no longer error — see above.)
pub fn parse_log_format(format: &str) -> Result<LogTemplate, LogFormatError> {
    let mut tokens: Vec<LogToken> = Vec::new();
    let mut chars = format.chars().peekable();
    let mut literal_buf = String::new();

    while let Some(&ch) = chars.peek() {
        if ch == '\\' {
            // Consume the backslash.
            chars.next();
            // The next character is the escaped one.
            match chars.next() {
                Some(escaped) => literal_buf.push(escaped),
                None => return Err(LogFormatError::UnclosedEscape),
            }
        } else if ch == '$' {
            // Consume the '$'.
            chars.next();
            // Collect the variable name: [a-zA-Z0-9_]+. Restrict to *ASCII*
            // alphanumerics — `is_alphanumeric()` (Bug) also accepted Unicode
            // letters, so e.g. `$statusÿ` folded the trailing `ÿ` into the
            // name and turned an otherwise-valid `$status` into an error.
            let mut var_name = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_ascii_alphanumeric() || c == '_' {
                    var_name.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            // Bug: the parser unconditionally entered the variable branch on
            // `$` and returned UnknownVariable when the name was empty or not
            // recognized — rejecting inputs NGINX accepts (`price=$5`,
            // `cost: $ done`, `a$$b`). Fix: a `$` that does not form a known
            // variable is emitted as a literal (NGINX-compatible) instead of
            // erroring. We keep the `$` and the collected (non-variable) name
            // in the literal buffer, then continue scanning normally.
            match LogVariable::from_str(&var_name) {
                Some(var) => {
                    // Flush any accumulated literal before the variable token.
                    if !literal_buf.is_empty() {
                        tokens.push(LogToken::Literal(std::mem::take(&mut literal_buf)));
                    }
                    tokens.push(LogToken::Variable(var));
                }
                None => {
                    // Not a recognized variable: treat `$<name>` as literal text.
                    literal_buf.push('$');
                    literal_buf.push_str(&var_name);
                }
            }
        } else {
            literal_buf.push(ch);
            chars.next();
        }
    }

    // Flush trailing literal.
    if !literal_buf.is_empty() {
        tokens.push(LogToken::Literal(literal_buf));
    }

    // The generic parser cannot know a caller's intent, so custom templates
    // get NGINX-style text escaping (which still neutralizes CRLF forging).
    // The one format the engine itself knows to be JSON is its own preset, so
    // detect that exactly and flag it for JSON escaping; this also covers the
    // documented `parse_log_format(JSON_FORMAT)?.render(&ctx)` call path.
    let escape = if format == JSON_FORMAT {
        ValueEscape::Json
    } else {
        ValueEscape::Text
    };

    Ok(LogTemplate {
        tokens,
        name: String::from("custom"),
        escape,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// LogContext — per-request rendering context
// ═══════════════════════════════════════════════════════════════════════════

/// All the fields a log line could reference. Optional fields render as `-`
/// when absent, matching NGINX convention.
#[derive(Clone, Debug, Default)]
pub struct LogContext {
    /// Client IP address.
    pub remote_addr: String,
    /// Client port.
    pub remote_port: Option<u16>,
    /// Local time in Common Log Format, e.g. `10/Oct/2000:13:55:36 -0700`.
    pub time_local: String,
    /// ISO 8601 timestamp.
    pub time_iso8601: String,
    /// HTTP method (GET, POST, ...).
    pub method: String,
    /// Request URI path.
    pub uri: String,
    /// HTTP protocol version string (e.g. `HTTP/1.1`).
    pub protocol: String,
    /// HTTP response status code.
    pub status: u16,
    /// Bytes sent in response body (excluding headers).
    pub body_bytes_sent: u64,
    /// Total bytes sent including headers.
    pub bytes_sent: Option<u64>,
    /// HTTP Referer header.
    pub http_referer: Option<String>,
    /// HTTP User-Agent header.
    pub http_user_agent: Option<String>,
    /// Request processing time.
    pub request_time: Option<Duration>,
    /// Upstream server address (host:port).
    pub upstream_addr: Option<String>,
    /// Upstream response status code.
    pub upstream_status: Option<u16>,
    /// Upstream response time.
    pub upstream_response_time: Option<Duration>,
    /// Total request length including headers + body.
    pub request_length: Option<u64>,
    /// Connection serial number.
    pub connection: Option<u64>,
    /// Number of requests on this connection.
    pub connection_requests: Option<u64>,
    /// Request scheme (http/https).
    pub scheme: Option<String>,
    /// Host header value.
    pub host: Option<String>,
    /// Matched service name in the gateway.
    pub service_name: Option<String>,
    /// Matched service ID.
    pub service_id: Option<String>,
    /// Matched route ID.
    pub route_id: Option<String>,
    /// Authenticated consumer username.
    pub consumer_username: Option<String>,
    /// Unique request identifier.
    pub request_id: Option<String>,
}

impl LogContext {
    /// Resolve a `LogVariable` to its string representation. Missing
    /// optional fields return `"-"`.
    fn resolve(&self, var: &LogVariable) -> String {
        match var {
            LogVariable::RemoteAddr => self.remote_addr.clone(),
            LogVariable::RemotePort => self
                .remote_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".into()),
            LogVariable::TimeLocal => self.time_local.clone(),
            LogVariable::TimeIso8601 => self.time_iso8601.clone(),
            LogVariable::Request => {
                format!("{} {} {}", self.method, self.uri, self.protocol)
            }
            LogVariable::Status => self.status.to_string(),
            LogVariable::BodyBytesSent => self.body_bytes_sent.to_string(),
            LogVariable::BytesSent => self
                .bytes_sent
                .map(|b| b.to_string())
                .unwrap_or_else(|| "-".into()),
            LogVariable::HttpReferer => opt_str(&self.http_referer),
            LogVariable::HttpUserAgent => opt_str(&self.http_user_agent),
            LogVariable::RequestTime => self
                .request_time
                .map(|d| format!("{:.3}", d.as_secs_f64()))
                .unwrap_or_else(|| "-".into()),
            LogVariable::UpstreamAddr => opt_str(&self.upstream_addr),
            LogVariable::UpstreamStatus => self
                .upstream_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".into()),
            LogVariable::UpstreamResponseTime => self
                .upstream_response_time
                .map(|d| format!("{:.3}", d.as_secs_f64()))
                .unwrap_or_else(|| "-".into()),
            LogVariable::RequestLength => self
                .request_length
                .map(|l| l.to_string())
                .unwrap_or_else(|| "-".into()),
            LogVariable::Connection => self
                .connection
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".into()),
            LogVariable::ConnectionRequests => self
                .connection_requests
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".into()),
            LogVariable::Scheme => opt_str(&self.scheme),
            LogVariable::Host => opt_str(&self.host),
            LogVariable::Uri => self.uri.clone(),
            LogVariable::Method => self.method.clone(),
            LogVariable::Protocol => self.protocol.clone(),
            LogVariable::ServiceName => opt_str(&self.service_name),
            LogVariable::ServiceId => opt_str(&self.service_id),
            LogVariable::RouteId => opt_str(&self.route_id),
            LogVariable::ConsumerUsername => opt_str(&self.consumer_username),
            LogVariable::RequestId => opt_str(&self.request_id),
        }
    }
}

/// Helper: extract `Option<String>` to owned string, defaulting to `"-"`.
#[inline]
fn opt_str(opt: &Option<String>) -> String {
    match opt {
        Some(s) => s.clone(),
        None => "-".into(),
    }
}

/// Escape a resolved value for a human-readable (text) log line.
///
/// Bug: resolved values (request headers, URI, ...) were emitted verbatim, so
/// a value containing `\n`/`\r` split one log line into two physical lines and
/// let an attacker forge a fake access-log record (CWE-117). Mirroring NGINX's
/// default access-log escaping, every C0 control character (`0x00..=0x1F`,
/// which includes `\t`, `\r`, `\n`) and DEL (`0x7F`) is rendered as `\xNN` so a
/// value can never break out onto a new line. Other bytes pass through
/// unchanged, preserving the existing look of Combined/Common output.
fn escape_log_value_text(value: &str) -> String {
    // Fast path: the overwhelming majority of values contain no control chars.
    if !value.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len() + 8);
    for ch in value.chars() {
        let c = ch as u32;
        if c < 0x20 || c == 0x7F {
            // Always representable as exactly two hex digits (c <= 0x7F here).
            out.push_str(&format!("\\x{:02X}", c));
        } else {
            out.push(ch);
        }
    }
    out
}

/// Escape a resolved value for embedding inside a JSON string literal.
///
/// Bug: the JSON preset wrapped every `$var` in literal quotes but emitted the
/// resolved value verbatim, so a value containing `"`, `\`, or a control char
/// produced invalid JSON and allowed forged top-level keys (e.g. a User-Agent
/// of `x","status":"200","injected":"1`). This performs full JSON
/// string-content escaping so the rendered line is always valid JSON and a
/// value can never terminate its surrounding string literal.
fn escape_log_value_json(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            // Remaining C0 control characters have no short escape: use \u00XX.
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Apply the template's configured escaping to a resolved value.
#[inline]
fn escape_value(value: &str, mode: ValueEscape) -> String {
    match mode {
        ValueEscape::Text => escape_log_value_text(value),
        ValueEscape::Json => escape_log_value_json(value),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Rendering
// ═══════════════════════════════════════════════════════════════════════════

impl LogTemplate {
    /// Render this template against the given request context, producing a
    /// complete log line. Variables are substituted with values from `ctx`;
    /// literals are emitted verbatim.
    pub fn render(&self, ctx: &LogContext) -> String {
        let mut out = String::with_capacity(256);
        for token in &self.tokens {
            match token {
                // Literals come from the (trusted) format string itself, so
                // they are emitted verbatim. Only resolved *values* are
                // attacker-influenced and therefore escaped per `self.escape`
                // (Text => CRLF-forging-safe \xNN; Json => valid-JSON escaping).
                LogToken::Literal(s) => out.push_str(s),
                LogToken::Variable(var) => {
                    out.push_str(&escape_value(&ctx.resolve(var), self.escape))
                }
            }
        }
        LOG_FORMAT_METRICS
            .lines_rendered
            .fetch_add(1, Ordering::Relaxed);
        out
    }
}

/// Convenience: render a preset format against a `LogContext` without
/// manually parsing the template each time. Uses pre-parsed templates.
pub fn render_preset(preset: LogFormatPreset, ctx: &LogContext) -> String {
    let format_str = match preset {
        LogFormatPreset::Combined => COMBINED_FORMAT,
        LogFormatPreset::Common => COMMON_FORMAT,
        LogFormatPreset::Json => JSON_FORMAT,
        LogFormatPreset::Custom => {
            // Custom requires a pre-parsed template; fall back to combined.
            COMBINED_FORMAT
        }
    };
    // These presets are known-good, so unwrap is safe.
    let mut template = parse_log_format(format_str).expect("preset format is always valid");
    // Bug: the JSON preset string-templated raw values into quoted slots,
    // producing invalid JSON / allowing key injection. Force JSON escaping for
    // the JSON preset explicitly (rather than relying on the format-string
    // match in `parse_log_format`) so the output is always valid JSON.
    template.escape = match preset {
        LogFormatPreset::Json => ValueEscape::Json,
        _ => ValueEscape::Text,
    };
    template.render(ctx)
}

// ═══════════════════════════════════════════════════════════════════════════
// LogFormatMetrics — atomic counters
// ═══════════════════════════════════════════════════════════════════════════

/// Atomic counters for log format rendering operations.
pub struct LogFormatMetrics {
    /// Total log lines successfully rendered.
    pub lines_rendered: AtomicU64,
    /// Total render errors (e.g. template referenced a variable that
    /// somehow failed to resolve — defensive counter).
    pub render_errors: AtomicU64,
}

impl LogFormatMetrics {
    /// Create a new zeroed metrics instance.
    const fn new() -> Self {
        Self {
            lines_rendered: AtomicU64::new(0),
            render_errors: AtomicU64::new(0),
        }
    }

    /// Read the current lines_rendered count.
    pub fn lines_rendered(&self) -> u64 {
        self.lines_rendered.load(Ordering::Relaxed)
    }

    /// Read the current render_errors count.
    pub fn render_errors(&self) -> u64 {
        self.render_errors.load(Ordering::Relaxed)
    }

    /// Reset all counters to zero.
    pub fn reset(&self) {
        self.lines_rendered.store(0, Ordering::Relaxed);
        self.render_errors.store(0, Ordering::Relaxed);
    }
}

/// Global metrics instance for log format rendering.
pub static LOG_FORMAT_METRICS: LogFormatMetrics = LogFormatMetrics::new();

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a fully-populated LogContext for rendering tests.
    fn full_context() -> LogContext {
        LogContext {
            remote_addr: "192.168.1.100".into(),
            remote_port: Some(54321),
            time_local: "23/May/2026:14:30:00 +0000".into(),
            time_iso8601: "2026-05-23T14:30:00+00:00".into(),
            method: "GET".into(),
            uri: "/api/v1/users".into(),
            protocol: "HTTP/1.1".into(),
            status: 200,
            body_bytes_sent: 1234,
            bytes_sent: Some(1500),
            http_referer: Some("https://example.com/page".into()),
            http_user_agent: Some("Mozilla/5.0".into()),
            request_time: Some(Duration::from_millis(42)),
            upstream_addr: Some("10.0.0.1:8080".into()),
            upstream_status: Some(200),
            upstream_response_time: Some(Duration::from_millis(38)),
            request_length: Some(256),
            connection: Some(12345),
            connection_requests: Some(3),
            scheme: Some("https".into()),
            host: Some("api.example.com".into()),
            service_name: Some("user-service".into()),
            service_id: Some("svc-001".into()),
            route_id: Some("rt-042".into()),
            consumer_username: Some("alice".into()),
            request_id: Some("req-abc-123".into()),
        }
    }

    // ── Parse tests ──────────────────────────────────────────────────────

    #[test]
    fn parse_simple_literal() {
        let tpl = parse_log_format("hello world").unwrap();
        assert_eq!(tpl.tokens, vec![LogToken::Literal("hello world".into())]);
    }

    #[test]
    fn parse_single_variable() {
        let tpl = parse_log_format("$status").unwrap();
        assert_eq!(tpl.tokens, vec![LogToken::Variable(LogVariable::Status)]);
    }

    #[test]
    fn parse_mixed_literal_and_variable() {
        let tpl = parse_log_format("code=$status ok").unwrap();
        assert_eq!(
            tpl.tokens,
            vec![
                LogToken::Literal("code=".into()),
                LogToken::Variable(LogVariable::Status),
                LogToken::Literal(" ok".into()),
            ]
        );
    }

    #[test]
    fn parse_multiple_variables() {
        let tpl = parse_log_format("$method $uri $protocol").unwrap();
        assert_eq!(
            tpl.tokens,
            vec![
                LogToken::Variable(LogVariable::Method),
                LogToken::Literal(" ".into()),
                LogToken::Variable(LogVariable::Uri),
                LogToken::Literal(" ".into()),
                LogToken::Variable(LogVariable::Protocol),
            ]
        );
    }

    #[test]
    fn parse_combined_format_preset() {
        let tpl = parse_log_format(COMBINED_FORMAT).unwrap();
        // Should contain variables: remote_addr, consumer_username, time_local,
        // request, status, body_bytes_sent, http_referer, http_user_agent.
        let vars: Vec<&LogVariable> = tpl
            .tokens
            .iter()
            .filter_map(|t| match t {
                LogToken::Variable(v) => Some(v),
                _ => None,
            })
            .collect();
        assert_eq!(vars.len(), 8);
        assert_eq!(vars[0], &LogVariable::RemoteAddr);
        assert_eq!(vars[1], &LogVariable::ConsumerUsername);
        assert_eq!(vars[7], &LogVariable::HttpUserAgent);
    }

    #[test]
    fn parse_common_format_preset() {
        let tpl = parse_log_format(COMMON_FORMAT).unwrap();
        let vars: Vec<&LogVariable> = tpl
            .tokens
            .iter()
            .filter_map(|t| match t {
                LogToken::Variable(v) => Some(v),
                _ => None,
            })
            .collect();
        assert_eq!(vars.len(), 6);
        assert_eq!(vars[5], &LogVariable::BodyBytesSent);
    }

    #[test]
    fn parse_unknown_variable_is_literal() {
        // Bug fix: an unrecognized `$name` is no longer an error — NGINX leaves
        // such sequences in place, so we re-emit `$nonexistent_var` verbatim as
        // a single literal token instead of returning UnknownVariable.
        let tpl = parse_log_format("$nonexistent_var").unwrap();
        assert_eq!(
            tpl.tokens,
            vec![LogToken::Literal("$nonexistent_var".into())]
        );
    }

    #[test]
    fn parse_escaped_quote() {
        let tpl = parse_log_format(r#"\"$request\""#).unwrap();
        assert_eq!(
            tpl.tokens,
            vec![
                LogToken::Literal("\"".into()),
                LogToken::Variable(LogVariable::Request),
                LogToken::Literal("\"".into()),
            ]
        );
    }

    #[test]
    fn parse_empty_string() {
        let tpl = parse_log_format("").unwrap();
        assert!(tpl.tokens.is_empty());
    }

    // ── Render tests ─────────────────────────────────────────────────────

    #[test]
    fn render_all_fields_populated() {
        let tpl = parse_log_format("$remote_addr:$remote_port $method $uri $status").unwrap();
        let ctx = full_context();
        let line = tpl.render(&ctx);
        assert_eq!(line, "192.168.1.100:54321 GET /api/v1/users 200");
    }

    #[test]
    fn render_missing_optional_fields() {
        let tpl = parse_log_format("$upstream_addr $upstream_status $http_referer").unwrap();
        let ctx = LogContext::default();
        let line = tpl.render(&ctx);
        assert_eq!(line, "- - -");
    }

    #[test]
    fn render_combined_format() {
        let ctx = full_context();
        let line = render_preset(LogFormatPreset::Combined, &ctx);
        assert!(line.starts_with("192.168.1.100 - alice [23/May/2026:14:30:00 +0000]"));
        assert!(line.contains("\"GET /api/v1/users HTTP/1.1\""));
        assert!(line.contains("200 1234"));
        assert!(line.contains("\"https://example.com/page\""));
        assert!(line.contains("\"Mozilla/5.0\""));
    }

    #[test]
    fn render_common_format() {
        let ctx = full_context();
        let line = render_preset(LogFormatPreset::Common, &ctx);
        assert!(line.starts_with("192.168.1.100 - alice [23/May/2026:14:30:00 +0000]"));
        assert!(line.contains("200 1234"));
        // Common format should NOT contain referer/user-agent.
        assert!(!line.contains("Mozilla"));
    }

    #[test]
    fn render_json_format() {
        let ctx = full_context();
        let line = render_preset(LogFormatPreset::Json, &ctx);
        assert!(line.starts_with('{'));
        assert!(line.ends_with('}'));
        assert!(line.contains("\"remote_addr\":\"192.168.1.100\""));
        assert!(line.contains("\"status\":\"200\""));
        assert!(line.contains("\"request_id\":\"req-abc-123\""));
    }

    // ── Variable mapping tests ───────────────────────────────────────────

    #[test]
    fn log_variable_from_string_mapping() {
        assert_eq!(
            LogVariable::from_str("remote_addr"),
            Some(LogVariable::RemoteAddr)
        );
        assert_eq!(LogVariable::from_str("status"), Some(LogVariable::Status));
        assert_eq!(
            LogVariable::from_str("request_time"),
            Some(LogVariable::RequestTime)
        );
        assert_eq!(
            LogVariable::from_str("consumer_username"),
            Some(LogVariable::ConsumerUsername)
        );
        assert_eq!(LogVariable::from_str("bogus"), None);
    }

    // ── Preset roundtrip ─────────────────────────────────────────────────

    #[test]
    fn log_format_preset_from_u8_roundtrip() {
        for &preset in &[
            LogFormatPreset::Combined,
            LogFormatPreset::Common,
            LogFormatPreset::Json,
            LogFormatPreset::Custom,
        ] {
            assert_eq!(LogFormatPreset::from_u8(preset.as_u8()), preset);
        }
        // Unknown value falls back to Combined.
        assert_eq!(LogFormatPreset::from_u8(99), LogFormatPreset::Combined);
    }

    // ── Global enable/disable ────────────────────────────────────────────

    #[test]
    fn global_enable_disable() {
        // Should be enabled by default.
        assert!(is_log_format_enabled());
        set_log_format_enabled(false);
        assert!(!is_log_format_enabled());
        // Restore.
        set_log_format_enabled(true);
        assert!(is_log_format_enabled());
    }

    // ── LogContext default ───────────────────────────────────────────────

    #[test]
    fn log_context_default() {
        let ctx = LogContext::default();
        assert!(ctx.remote_addr.is_empty());
        assert_eq!(ctx.status, 0);
        assert_eq!(ctx.body_bytes_sent, 0);
        assert!(ctx.http_referer.is_none());
        assert!(ctx.upstream_addr.is_none());
        assert!(ctx.consumer_username.is_none());
    }

    // ── Request time precision ───────────────────────────────────────────

    #[test]
    fn render_request_time_with_ms_precision() {
        let tpl = parse_log_format("$request_time").unwrap();
        let ctx = LogContext {
            request_time: Some(Duration::from_millis(1234)),
            ..Default::default()
        };
        let line = tpl.render(&ctx);
        assert_eq!(line, "1.234");
    }

    // ── Literal whitespace/brackets preserved ────────────────────────────

    #[test]
    fn render_preserves_literal_whitespace_and_brackets() {
        let tpl = parse_log_format("[$time_local]  {$status}").unwrap();
        let ctx = LogContext {
            time_local: "NOW".into(),
            status: 404,
            ..Default::default()
        };
        let line = tpl.render(&ctx);
        assert_eq!(line, "[NOW]  {404}");
    }

    // ── Metrics counting ─────────────────────────────────────────────────

    #[test]
    fn metrics_counting() {
        LOG_FORMAT_METRICS.reset();
        assert_eq!(LOG_FORMAT_METRICS.lines_rendered(), 0);
        assert_eq!(LOG_FORMAT_METRICS.render_errors(), 0);

        let tpl = parse_log_format("$status").unwrap();
        let ctx = LogContext {
            status: 200,
            ..Default::default()
        };
        tpl.render(&ctx);
        tpl.render(&ctx);
        tpl.render(&ctx);

        // lines_rendered should be at least 3 (other tests may also
        // increment the global, but reset above clears it).
        assert!(LOG_FORMAT_METRICS.lines_rendered() >= 3);
    }

    // ── UnclosedEscape error ─────────────────────────────────────────────

    #[test]
    fn parse_unclosed_escape_error() {
        let err = parse_log_format("trailing\\").unwrap_err();
        assert_eq!(err, LogFormatError::UnclosedEscape);
    }

    // ── Regression: JSON preset escapes values (Bug: invalid JSON / key
    //    injection because values were never escaped) ──────────────────────

    #[test]
    fn render_json_escapes_quotes_and_controls() {
        // A User-Agent carrying `"`, `\`, and control chars. Pre-fix this
        // produced invalid JSON (`"http_user_agent":"a"b"`) and could inject
        // forged top-level keys; post-fix the line must parse as valid JSON
        // with a single `http_user_agent` key whose value round-trips exactly.
        let injection = "a\"b\\c\n\tx\",\"injected\":\"1";
        let ctx = LogContext {
            http_user_agent: Some(injection.into()),
            status: 200,
            ..Default::default()
        };
        let line = render_preset(LogFormatPreset::Json, &ctx);

        let parsed: serde_json::Value =
            serde_json::from_str(&line).expect("JSON preset must emit valid JSON");
        let obj = parsed.as_object().expect("top level must be a JSON object");

        // The malicious value did NOT create an extra top-level key.
        assert!(
            obj.get("injected").is_none(),
            "value injection created a forged top-level key: {line}"
        );
        // The value survives intact (escaping is lossless on decode).
        assert_eq!(
            obj.get("http_user_agent").and_then(|v| v.as_str()),
            Some(injection)
        );
        // And a normal field is unaffected.
        assert_eq!(obj.get("status").and_then(|v| v.as_str()), Some("200"));
    }

    #[test]
    fn render_json_plain_values_unchanged() {
        // Escaping must not alter values that contain no special characters,
        // so the existing structured-output shape is preserved.
        let ctx = full_context();
        let line = render_preset(LogFormatPreset::Json, &ctx);
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["remote_addr"], "192.168.1.100");
        assert_eq!(parsed["request_id"], "req-abc-123");
        assert_eq!(parsed["status"], "200");
    }

    // ── Regression: Combined/Common neutralize CRLF log forging
    //    (Bug: header-derived values emitted verbatim, splitting the line) ──

    #[test]
    fn render_combined_neutralizes_crlf_forging() {
        // Attacker-controlled User-Agent tries to forge a second log record.
        let forged = "Mozilla\r\n10.0.0.9 - admin [x] \"GET /forged\" 200 0";
        let ctx = LogContext {
            http_user_agent: Some(forged.into()),
            ..full_context()
        };
        let line = render_preset(LogFormatPreset::Combined, &ctx);
        // The rendered record must remain a single physical line: no raw CR/LF
        // may survive into the output.
        assert!(
            !line.contains('\n') && !line.contains('\r'),
            "CRLF forging not neutralized: {line:?}"
        );
        // The control bytes are rendered as visible \xNN escapes instead.
        assert!(line.contains("\\x0D\\x0A"), "expected escaped CRLF in {line:?}");
    }

    #[test]
    fn render_custom_template_neutralizes_control_chars() {
        // Text escaping applies to ALL presets including Custom templates.
        let ctx = LogContext {
            http_referer: Some("foo\nbar".into()),
            ..Default::default()
        };
        let tpl = parse_log_format("ref=$http_referer").unwrap();
        let line = tpl.render(&ctx);
        assert!(!line.contains('\n'));
        assert_eq!(line, "ref=foo\\x0Abar");
    }

    // ── Regression: parser accepts literal `$` / `$`-before-non-variable
    //    that NGINX accepts (Bug: returned UnknownVariable) ────────────────

    #[test]
    fn parse_literal_dollar_before_digits() {
        // `$5` is not a known variable → emitted as literal `$5`, not an error.
        let tpl = parse_log_format("price=$5").unwrap();
        assert_eq!(tpl.tokens, vec![LogToken::Literal("price=$5".into())]);
    }

    #[test]
    fn parse_bare_dollar_sign() {
        // A `$` followed by a non-name char (space) is a literal `$`.
        let tpl = parse_log_format("cost: $ done").unwrap();
        assert_eq!(tpl.tokens, vec![LogToken::Literal("cost: $ done".into())]);
    }

    #[test]
    fn parse_double_dollar_sign() {
        let tpl = parse_log_format("a$$b").unwrap();
        assert_eq!(tpl.tokens, vec![LogToken::Literal("a$$b".into())]);
    }

    #[test]
    fn parse_unicode_after_valid_variable() {
        // The name class is ASCII-only, so a trailing Unicode letter is NOT
        // absorbed into the variable name; `$status` resolves and `ÿ` is a
        // literal that follows it.
        let tpl = parse_log_format("$status\u{00ff}").unwrap();
        assert_eq!(
            tpl.tokens,
            vec![
                LogToken::Variable(LogVariable::Status),
                LogToken::Literal("\u{00ff}".into()),
            ]
        );
    }
}
