//! Branded HTML error pages served when the client wants HTML (browsers).
//!
//! Plain JSON stays the default for API/SDK callers; the HTML variant is only
//! produced when the `Accept` header asks for `text/html`. Pages are
//! self-contained — no external CSS, fonts, or JS — so they render even when
//! upstream/CDN is unreachable.

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, Response, StatusCode};

const ROUTE_NOT_FOUND_HTML: &str = include_str!("route_not_found.html");

/// Cheap check: does the client want HTML? (Browsers send `text/html` in
/// their Accept; curl/SDKs typically don't.)
pub fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("text/html"))
        .unwrap_or(false)
}

/// Render the 404 route-not-found page with the offending path inlined.
/// The path is HTML-escaped before substitution so a malicious request like
/// `/?<script>` can't inject markup.
pub fn render_route_not_found(path: &str) -> Response<Body> {
    let escaped = html_escape(path);
    let body = ROUTE_NOT_FOUND_HTML.replace("{{path}}", &escaped);
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = StatusCode::NOT_FOUND;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn wants_html_browser() {
        let mut h = HeaderMap::new();
        h.insert(
            header::ACCEPT,
            HeaderValue::from_static("text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"),
        );
        assert!(wants_html(&h));
    }

    #[test]
    fn wants_html_api_client() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        assert!(!wants_html(&h));
    }

    #[test]
    fn wants_html_no_header() {
        let h = HeaderMap::new();
        assert!(!wants_html(&h));
    }

    #[test]
    fn html_escape_neutralises_injection() {
        assert_eq!(
            html_escape("/<script>alert('x')</script>"),
            "/&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"
        );
        assert_eq!(html_escape("/a&b\"c"), "/a&amp;b&quot;c");
    }

    #[test]
    fn render_inlines_escaped_path() {
        let resp = render_route_not_found("/a<b>");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
    }
}
