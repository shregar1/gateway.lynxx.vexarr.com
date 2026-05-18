//! FastCGI client transport.
//!
//! Implements the FastCGI protocol (spec version 1.0) so Lynxx can
//! proxy requests to PHP-FPM, Python WSGI/ASGI adapters, or any
//! FastCGI-speaking backend. Equivalent to Caddy's `php_fastcgi` and
//! `reverse_proxy` with `transport fastcgi`.
//!
//! ## Config
//!
//! Set `service_type = "fastcgi"` and `url = "unix:///run/php/php-fpm.sock"`
//! or `url = "tcp://127.0.0.1:9000"` on the service. Additional config:
//!
//! ```toml
//! [service]
//! service_type = "fastcgi"
//! url          = "unix:///run/php/php-fpm.sock"
//! document_root = "/var/www/html"
//! index_file    = "index.php"
//! ```

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// FastCGI record types
const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_ABORT_REQUEST: u8 = 2;
const FCGI_END_REQUEST: u8 = 3;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDIN: u8 = 5;
const FCGI_STDOUT: u8 = 6;
const FCGI_STDERR: u8 = 7;

// FastCGI roles
const FCGI_RESPONDER: u16 = 1;

// FastCGI flags
const FCGI_KEEP_CONN: u8 = 1;

/// A single FastCGI record header (8 bytes).
struct FcgiRecord {
    version: u8,
    record_type: u8,
    request_id: u16,
    content_length: u16,
    padding_length: u8,
}

impl FcgiRecord {
    fn to_bytes(&self) -> [u8; 8] {
        let id = self.request_id.to_be_bytes();
        let len = self.content_length.to_be_bytes();
        [
            self.version,
            self.record_type,
            id[0],
            id[1],
            len[0],
            len[1],
            self.padding_length,
            0, // reserved
        ]
    }
}

/// Encode a single name-value pair in FastCGI format.
fn encode_param(name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + name.len() + value.len());
    encode_length(&mut buf, name.len());
    encode_length(&mut buf, value.len());
    buf.extend_from_slice(name);
    buf.extend_from_slice(value);
    buf
}

fn encode_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else {
        let len = len as u32;
        buf.push(((len >> 24) & 0x7F) as u8 | 0x80);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

/// Build a FCGI_BEGIN_REQUEST record.
fn begin_request(request_id: u16) -> Vec<u8> {
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(&FCGI_RESPONDER.to_be_bytes());
    body.push(FCGI_KEEP_CONN);
    body.extend_from_slice(&[0; 5]); // reserved
    let hdr = FcgiRecord {
        version: 1,
        record_type: FCGI_BEGIN_REQUEST,
        request_id,
        content_length: 8,
        padding_length: 0,
    };
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&hdr.to_bytes());
    out.extend_from_slice(&body);
    out
}

/// Build a FCGI_PARAMS record from the given pairs.
fn params_record(request_id: u16, params: &[(&str, &str)]) -> Vec<u8> {
    let mut payload = Vec::new();
    for (name, value) in params {
        payload.extend(encode_param(name.as_bytes(), value.as_bytes()));
    }

    let mut out = Vec::new();
    // Send params in chunks of up to 65535 bytes
    for chunk in payload.chunks(65535) {
        let padding = (8 - (chunk.len() % 8)) % 8;
        let hdr = FcgiRecord {
            version: 1,
            record_type: FCGI_PARAMS,
            request_id,
            content_length: chunk.len() as u16,
            padding_length: padding as u8,
        };
        out.extend_from_slice(&hdr.to_bytes());
        out.extend_from_slice(chunk);
        out.extend(std::iter::repeat_n(0, padding));
    }

    // Empty FCGI_PARAMS to signal end
    let hdr = FcgiRecord {
        version: 1,
        record_type: FCGI_PARAMS,
        request_id,
        content_length: 0,
        padding_length: 0,
    };
    out.extend_from_slice(&hdr.to_bytes());
    out
}

/// Build a FCGI_STDIN record.
fn stdin_record(request_id: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in data.chunks(65535) {
        let padding = (8 - (chunk.len() % 8)) % 8;
        let hdr = FcgiRecord {
            version: 1,
            record_type: FCGI_STDIN,
            request_id,
            content_length: chunk.len() as u16,
            padding_length: padding as u8,
        };
        out.extend_from_slice(&hdr.to_bytes());
        out.extend_from_slice(chunk);
        out.extend(std::iter::repeat_n(0, padding));
    }
    // Empty FCGI_STDIN to signal EOF
    let hdr = FcgiRecord {
        version: 1,
        record_type: FCGI_STDIN,
        request_id,
        content_length: 0,
        padding_length: 0,
    };
    out.extend_from_slice(&hdr.to_bytes());
    out
}

/// Send a request to a FastCGI backend and return the HTTP response.
///
/// `upstream_url` is either `unix:///path/to/sock` or `tcp://host:port`.
pub async fn send_fastcgi(
    req: Request<Body>,
    upstream_url: &str,
    document_root: &str,
    script_name: &str,
) -> Result<Response<Body>, FastcgiError> {
    let request_id: u16 = 1;

    // Extract request metadata (all owned so we can consume the body)
    let method = req.method().to_string();
    let uri = req.uri().clone();
    let request_uri = uri.to_string();
    let query = uri.query().unwrap_or("").to_string();
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost")
        .to_string();
    let content_type = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let content_length_val = req
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("0")
        .to_string();

    // Collect body
    let body_bytes = req
        .into_body()
        .collect()
        .await
        .map_err(|e| FastcgiError::Body(e.to_string()))?
        .to_bytes();

    // Build CGI params
    let script_filename = format!("{document_root}/{script_name}");
    let params: Vec<(&str, &str)> = vec![
        ("GATEWAY_INTERFACE", "FastCGI/1.0"),
        ("SERVER_PROTOCOL", "HTTP/1.1"),
        ("REQUEST_METHOD", &method),
        ("SCRIPT_FILENAME", &script_filename),
        ("SCRIPT_NAME", script_name),
        ("DOCUMENT_ROOT", document_root),
        ("REQUEST_URI", &request_uri),
        ("QUERY_STRING", &query),
        ("SERVER_NAME", &host),
        ("SERVER_PORT", "443"),
        ("CONTENT_TYPE", &content_type),
        ("CONTENT_LENGTH", &content_length_val),
    ];

    // Connect to FastCGI backend and exchange records
    let payload = build_payload(request_id, &params, &body_bytes);

    #[cfg(unix)]
    if let Some(path) = upstream_url.strip_prefix("unix://") {
        let mut s = tokio::net::UnixStream::connect(path)
            .await
            .map_err(FastcgiError::Io)?;
        return fcgi_exchange(&mut s, &payload).await;
    }

    let addr = upstream_url
        .strip_prefix("tcp://")
        .or_else(|| upstream_url.strip_prefix("unix://"))
        .unwrap_or(upstream_url);
    let mut s = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(FastcgiError::Io)?;
    fcgi_exchange(&mut s, &payload).await
}

/// Build the full outbound FastCGI payload (BEGIN + PARAMS + STDIN).
fn build_payload(request_id: u16, params: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut payload = begin_request(request_id);
    payload.extend(params_record(request_id, params));
    payload.extend(stdin_record(request_id, body));
    payload
}

/// Send the payload and read response records over any async stream.
async fn fcgi_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    payload: &[u8],
) -> Result<Response<Body>, FastcgiError> {
    stream.write_all(payload).await.map_err(FastcgiError::Io)?;
    stream.flush().await.map_err(FastcgiError::Io)?;

    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    let mut ended = false;

    while !ended {
        let mut hdr_buf = [0u8; 8];
        stream
            .read_exact(&mut hdr_buf)
            .await
            .map_err(FastcgiError::Io)?;

        let record_type = hdr_buf[1];
        let content_length = u16::from_be_bytes([hdr_buf[4], hdr_buf[5]]) as usize;
        let padding_length = hdr_buf[6] as usize;

        let mut content = vec![0u8; content_length];
        if content_length > 0 {
            stream
                .read_exact(&mut content)
                .await
                .map_err(FastcgiError::Io)?;
        }
        if padding_length > 0 {
            let mut pad = vec![0u8; padding_length];
            stream
                .read_exact(&mut pad)
                .await
                .map_err(FastcgiError::Io)?;
        }

        match record_type {
            FCGI_STDOUT => stdout_buf.extend_from_slice(&content),
            FCGI_STDERR => stderr_buf.extend_from_slice(&content),
            FCGI_END_REQUEST => ended = true,
            _ => {}
        }
    }

    if !stderr_buf.is_empty() {
        let msg = String::from_utf8_lossy(&stderr_buf);
        tracing::warn!(stderr = %msg, "fastcgi backend stderr");
    }

    parse_cgi_response(&stdout_buf)
}

/// Parse raw CGI output into an HTTP response.
fn parse_cgi_response(data: &[u8]) -> Result<Response<Body>, FastcgiError> {
    // Find header/body separator: \r\n\r\n or \n\n
    let separator_pos = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| (p, 4))
        .or_else(|| data.windows(2).position(|w| w == b"\n\n").map(|p| (p, 2)));

    let (header_end, sep_len) = separator_pos.unwrap_or((data.len(), 0));
    let header_bytes = &data[..header_end];
    let body_start = header_end + sep_len;
    let body_bytes = if body_start < data.len() {
        &data[body_start..]
    } else {
        &[]
    };

    let headers_str = String::from_utf8_lossy(header_bytes);
    let mut builder = Response::builder();
    let mut status = StatusCode::OK;

    for line in headers_str.lines() {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if name.eq_ignore_ascii_case("Status") {
                if let Some(code_str) = value.split_whitespace().next() {
                    if let Ok(code) = code_str.parse::<u16>() {
                        status = StatusCode::from_u16(code).unwrap_or(StatusCode::OK);
                    }
                }
            } else {
                builder = builder.header(name, value);
            }
        }
    }

    builder
        .status(status)
        .body(Body::from(body_bytes.to_vec()))
        .map_err(|e| FastcgiError::Response(e.to_string()))
}

#[derive(Debug, thiserror::Error)]
pub enum FastcgiError {
    #[error("io: {0}")]
    Io(std::io::Error),
    #[error("body: {0}")]
    Body(String),
    #[error("response: {0}")]
    Response(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_short_param() {
        let encoded = encode_param(b"A", b"B");
        assert_eq!(encoded, vec![1, 1, b'A', b'B']);
    }

    #[test]
    fn encode_long_param() {
        let name = "X".repeat(200);
        let encoded = encode_param(name.as_bytes(), b"v");
        // Name length 200 > 127, so 4-byte encoding
        assert_eq!(encoded[0] & 0x80, 0x80);
        assert_eq!(encoded[4], 1); // value length
    }

    #[test]
    fn parse_cgi_simple() {
        let raw = b"Content-Type: text/html\r\nStatus: 200 OK\r\n\r\n<h1>Hello</h1>";
        let resp = parse_cgi_response(raw).unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn parse_cgi_404() {
        let raw = b"Status: 404 Not Found\nContent-Type: text/plain\n\nNot found";
        let resp = parse_cgi_response(raw).unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn begin_request_size() {
        let record = begin_request(1);
        assert_eq!(record.len(), 16); // 8-byte header + 8-byte body
    }
}
