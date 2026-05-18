//! Advanced route matchers: named matcher blocks, `not` negation,
//! `remote_ip`/`client_ip` CIDR matching, and `expression` (CEL-style)
//! evaluation. These extend the base path/method/host/header/query
//! matching that lives in `router.rs`.
//!
//! Matchers can be:
//! - Inlined on a route via `Route.matchers`
//! - Defined as named reusable blocks in the gateway config and
//!   referenced by routes with `Route.matcher_refs`

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// A single matcher condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Matcher {
    /// Match when the client's remote IP falls within one of the CIDR ranges.
    /// Uses the socket peer address (raw connection IP).
    RemoteIp { ranges: Vec<String> },
    /// Match when the logical client IP falls within one of the CIDR ranges.
    /// Uses X-Forwarded-For / X-Real-IP (respects trusted_proxies).
    ClientIp { ranges: Vec<String> },
    /// Negate an inner matcher.
    Not { matcher: Box<Matcher> },
    /// CEL-style expression evaluated against request context.
    /// Supported variables: `path`, `method`, `host`, `client_ip`,
    /// `header.<name>`, `query.<name>`, `path.matches("<regex>")`.
    Expression { expr: String },
    /// Header presence/value check (already on Route, but usable in
    /// named matcher blocks too).
    Header { name: String, value: String },
    /// Query parameter presence/value check.
    Query { name: String, value: String },
    /// Path prefix match.
    PathPrefix { prefix: String },
    /// Path regex match.
    PathRegex { pattern: String },
    /// Logical AND: all sub-matchers must pass.
    All { matchers: Vec<Matcher> },
    /// Logical OR: at least one sub-matcher must pass.
    Any { matchers: Vec<Matcher> },
    /// File existence matcher. Checks if any of the try_files paths exist
    /// on disk relative to the given root path.
    File {
        path: String,
        try_files: Vec<String>,
    },
    /// Protocol matcher. Matches the request scheme (http, https, grpc).
    Protocol { protocol: String },
    /// Variable exact-value matcher. Looks up a named variable from the
    /// route's vars map and checks for an exact match.
    Var { name: String, value: String },
    /// Variable regex matcher. Looks up a named variable from the route's
    /// vars map and matches against a regex pattern.
    VarRegex { name: String, pattern: String },
    /// Header regex matcher. Gets a header by name and matches its value
    /// against a regex pattern.
    HeaderRegex { name: String, pattern: String },
}

/// Named matcher block that can be referenced by multiple routes.
/// Analogous to Caddy's `@name` matcher syntax.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedMatcher {
    pub name: String,
    pub matchers: Vec<Matcher>,
}

/// Context passed to matcher evaluation — everything the matcher can
/// inspect about the current request.
pub struct MatcherContext<'a> {
    pub path: &'a str,
    pub method: &'a str,
    pub host: Option<&'a str>,
    pub remote_ip: Option<IpAddr>,
    pub client_ip: Option<&'a str>,
    pub headers: Option<&'a axum::http::HeaderMap>,
    pub query_string: Option<&'a str>,
    /// Request scheme (http, https, grpc). Used by the Protocol matcher.
    pub scheme: Option<&'a str>,
    /// Route-level variables. Used by Var and VarRegex matchers.
    pub vars: &'a HashMap<String, String>,
}

/// Registry of named matchers loaded from config.
#[derive(Debug, Clone, Default)]
pub struct MatcherRegistry {
    named: HashMap<String, Vec<Matcher>>,
}

impl MatcherRegistry {
    pub fn new() -> Self {
        Self {
            named: HashMap::new(),
        }
    }

    pub fn register(&mut self, name: String, matchers: Vec<Matcher>) {
        self.named.insert(name, matchers);
    }

    pub fn get(&self, name: &str) -> Option<&Vec<Matcher>> {
        self.named.get(name)
    }

    /// Load from a config list of named matchers.
    pub fn load_from_config(&mut self, named_matchers: &[NamedMatcher]) {
        for nm in named_matchers {
            self.named.insert(nm.name.clone(), nm.matchers.clone());
        }
    }
}

/// Evaluate a single matcher against the request context.
pub fn evaluate(matcher: &Matcher, ctx: &MatcherContext) -> bool {
    match matcher {
        Matcher::RemoteIp { ranges } => match_ip(ctx.remote_ip, ranges),
        Matcher::ClientIp { ranges } => {
            let ip = ctx
                .client_ip
                .and_then(|s| s.parse::<IpAddr>().ok())
                .or(ctx.remote_ip);
            match_ip(ip, ranges)
        }
        Matcher::Not { matcher: inner } => !evaluate(inner, ctx),
        Matcher::Expression { expr } => evaluate_expression(expr, ctx),
        Matcher::Header { name, value } => ctx
            .headers
            .and_then(|h| h.get(name.as_str()))
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case(value))
            .unwrap_or(false),
        Matcher::Query { name, value } => ctx
            .query_string
            .map(|qs| {
                qs.split('&')
                    .filter_map(|pair| pair.split_once('='))
                    .any(|(k, v)| k == name.as_str() && v == value.as_str())
            })
            .unwrap_or(false),
        Matcher::PathPrefix { prefix } => ctx.path.starts_with(prefix.as_str()),
        Matcher::PathRegex { pattern } => regex::Regex::new(pattern)
            .map(|re| re.is_match(ctx.path))
            .unwrap_or(false),
        Matcher::All { matchers } => matchers.iter().all(|m| evaluate(m, ctx)),
        Matcher::Any { matchers } => matchers.iter().any(|m| evaluate(m, ctx)),
        Matcher::File { path, try_files } => {
            let root = std::path::Path::new(path.as_str());
            try_files.iter().any(|f| root.join(f).exists())
        }
        Matcher::Protocol { protocol } => ctx
            .scheme
            .map(|s| s.eq_ignore_ascii_case(protocol))
            .unwrap_or(false),
        Matcher::Var { name, value } => ctx
            .vars
            .get(name.as_str())
            .map(|v| v == value)
            .unwrap_or(false),
        Matcher::VarRegex { name, pattern } => ctx
            .vars
            .get(name.as_str())
            .and_then(|v| regex::Regex::new(pattern).ok().map(|re| re.is_match(v)))
            .unwrap_or(false),
        Matcher::HeaderRegex { name, pattern } => ctx
            .headers
            .and_then(|h| h.get(name.as_str()))
            .and_then(|v| v.to_str().ok())
            .and_then(|v| regex::Regex::new(pattern).ok().map(|re| re.is_match(v)))
            .unwrap_or(false),
    }
}

/// Evaluate a list of matchers (implicit AND — all must pass).
pub fn evaluate_all(matchers: &[Matcher], ctx: &MatcherContext) -> bool {
    matchers.iter().all(|m| evaluate(m, ctx))
}

/// Check if an IP address matches any of the given CIDR ranges.
fn match_ip(ip: Option<IpAddr>, ranges: &[String]) -> bool {
    let ip = match ip {
        Some(ip) => ip,
        None => return false,
    };
    for range in ranges {
        if let Ok(net) = range.parse::<ipnet::IpNet>() {
            if net.contains(&ip) {
                return true;
            }
        }
        // Also try bare IP comparison.
        if let Ok(single) = range.parse::<IpAddr>() {
            if single == ip {
                return true;
            }
        }
    }
    false
}

/// Mini expression evaluator. Supports a practical subset:
///
/// - `path.startsWith("/api")`
/// - `path.matches("^/v[0-9]+")`
/// - `method == "POST"`
/// - `host == "example.com"`
/// - `header.X-Custom == "value"`
/// - `query.version == "2"`
/// - `client_ip in "10.0.0.0/8"`
/// - `!<expr>` (negation)
/// - `<expr> && <expr>` (AND)
/// - `<expr> || <expr>` (OR)
///
/// This is intentionally simple — not a full CEL engine, but covers the
/// most common Caddy expression matcher patterns.
fn evaluate_expression(expr: &str, ctx: &MatcherContext) -> bool {
    let expr = expr.trim();

    // Negation.
    if let Some(rest) = expr.strip_prefix('!') {
        return !evaluate_expression(rest.trim(), ctx);
    }

    // OR (lowest precedence) — split on top-level `||`.
    if let Some((left, right)) = split_top_level(expr, "||") {
        return evaluate_expression(left.trim(), ctx) || evaluate_expression(right.trim(), ctx);
    }

    // AND — split on top-level `&&`.
    if let Some((left, right)) = split_top_level(expr, "&&") {
        return evaluate_expression(left.trim(), ctx) && evaluate_expression(right.trim(), ctx);
    }

    // Parenthesised group.
    if expr.starts_with('(') && expr.ends_with(')') {
        return evaluate_expression(&expr[1..expr.len() - 1], ctx);
    }

    // path.startsWith("...")
    if let Some(rest) = expr.strip_prefix("path.startsWith(") {
        if let Some(arg) = extract_string_arg(rest) {
            return ctx.path.starts_with(&arg);
        }
    }

    // path.matches("...")
    if let Some(rest) = expr.strip_prefix("path.matches(") {
        if let Some(arg) = extract_string_arg(rest) {
            return regex::Regex::new(&arg)
                .map(|re| re.is_match(ctx.path))
                .unwrap_or(false);
        }
    }

    // method == "..."
    if let Some(rest) = expr.strip_prefix("method == ") {
        if let Some(val) = extract_quoted(rest.trim()) {
            return ctx.method.eq_ignore_ascii_case(&val);
        }
    }

    // host == "..."
    if let Some(rest) = expr.strip_prefix("host == ") {
        if let Some(val) = extract_quoted(rest.trim()) {
            return ctx
                .host
                .map(|h| h.eq_ignore_ascii_case(&val))
                .unwrap_or(false);
        }
    }

    // header.<Name> == "..."
    if let Some(rest) = expr.strip_prefix("header.") {
        if let Some((hdr_name, rhs)) = rest.split_once(" == ") {
            if let Some(val) = extract_quoted(rhs.trim()) {
                return ctx
                    .headers
                    .and_then(|h| h.get(hdr_name.trim()))
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v == val)
                    .unwrap_or(false);
            }
        }
    }

    // query.<Name> == "..."
    if let Some(rest) = expr.strip_prefix("query.") {
        if let Some((param_name, rhs)) = rest.split_once(" == ") {
            if let Some(val) = extract_quoted(rhs.trim()) {
                return ctx
                    .query_string
                    .map(|qs| {
                        qs.split('&')
                            .filter_map(|p| p.split_once('='))
                            .any(|(k, v)| k == param_name.trim() && v == val)
                    })
                    .unwrap_or(false);
            }
        }
    }

    // client_ip in "CIDR"
    if let Some(rest) = expr.strip_prefix("client_ip in ") {
        if let Some(cidr) = extract_quoted(rest.trim()) {
            let ip = ctx
                .client_ip
                .and_then(|s| s.parse::<IpAddr>().ok())
                .or(ctx.remote_ip);
            return match_ip(ip, &[cidr]);
        }
    }

    // remote_ip in "CIDR"
    if let Some(rest) = expr.strip_prefix("remote_ip in ") {
        if let Some(cidr) = extract_quoted(rest.trim()) {
            return match_ip(ctx.remote_ip, &[cidr]);
        }
    }

    // Fallback: unknown expression → false.
    tracing::warn!(expression = %expr, "unknown matcher expression; evaluating as false");
    false
}

/// Split on the first top-level occurrence of `sep` (not inside parens or quotes).
fn split_top_level<'a>(s: &'a str, sep: &str) -> Option<(&'a str, &'a str)> {
    let mut depth = 0u32;
    let mut in_quote = false;
    let bytes = s.as_bytes();
    let sep_bytes = sep.as_bytes();
    if sep_bytes.is_empty() || bytes.len() < sep_bytes.len() {
        return None;
    }
    let mut i = 0;
    while i <= bytes.len() - sep_bytes.len() {
        let b = bytes[i];
        if b == b'"' {
            in_quote = !in_quote;
        } else if !in_quote {
            if b == b'(' {
                depth += 1;
            } else if b == b')' {
                depth = depth.saturating_sub(1);
            } else if depth == 0 && &bytes[i..i + sep_bytes.len()] == sep_bytes {
                return Some((&s[..i], &s[i + sep_bytes.len()..]));
            }
        }
        i += 1;
    }
    None
}

/// Extract a string argument from `"value")...`.
fn extract_string_arg(s: &str) -> Option<String> {
    let s = s.trim();
    let s = s.strip_prefix('"')?;
    let end = s.find('"')?;
    Some(s[..end].to_string())
}

/// Extract a quoted string: `"value"` → `value`.
fn extract_quoted(s: &str) -> Option<String> {
    let s = s.trim();
    let s = s.strip_prefix('"')?;
    let s = s.strip_suffix('"')?;
    Some(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    static EMPTY_VARS: std::sync::LazyLock<HashMap<String, String>> =
        std::sync::LazyLock::new(HashMap::new);

    fn ctx_with_path(path: &str) -> MatcherContext<'_> {
        MatcherContext {
            path,
            method: "GET",
            host: Some("example.com"),
            remote_ip: Some("10.0.0.5".parse().unwrap()),
            client_ip: Some("192.168.1.100"),
            headers: None,
            query_string: None,
            scheme: None,
            vars: &EMPTY_VARS,
        }
    }

    // ── RemoteIp ──

    #[test]
    fn remote_ip_matches_cidr() {
        let m = Matcher::RemoteIp {
            ranges: vec!["10.0.0.0/8".to_string()],
        };
        let ctx = ctx_with_path("/");
        assert!(evaluate(&m, &ctx));
    }

    #[test]
    fn remote_ip_no_match() {
        let m = Matcher::RemoteIp {
            ranges: vec!["172.16.0.0/12".to_string()],
        };
        let ctx = ctx_with_path("/");
        assert!(!evaluate(&m, &ctx));
    }

    // ── ClientIp ──

    #[test]
    fn client_ip_matches() {
        let m = Matcher::ClientIp {
            ranges: vec!["192.168.1.0/24".to_string()],
        };
        let ctx = ctx_with_path("/");
        assert!(evaluate(&m, &ctx));
    }

    // ── Not ──

    #[test]
    fn not_negates_inner() {
        let m = Matcher::Not {
            matcher: Box::new(Matcher::RemoteIp {
                ranges: vec!["172.16.0.0/12".to_string()],
            }),
        };
        let ctx = ctx_with_path("/");
        assert!(evaluate(&m, &ctx)); // 10.0.0.5 NOT in 172.16/12 → true
    }

    #[test]
    fn not_negates_match() {
        let m = Matcher::Not {
            matcher: Box::new(Matcher::RemoteIp {
                ranges: vec!["10.0.0.0/8".to_string()],
            }),
        };
        let ctx = ctx_with_path("/");
        assert!(!evaluate(&m, &ctx)); // 10.0.0.5 in 10/8 → negated → false
    }

    // ── PathPrefix ──

    #[test]
    fn path_prefix_match() {
        let m = Matcher::PathPrefix {
            prefix: "/api/v2".to_string(),
        };
        assert!(evaluate(&m, &ctx_with_path("/api/v2/users")));
        assert!(!evaluate(&m, &ctx_with_path("/api/v1/users")));
    }

    // ── PathRegex ──

    #[test]
    fn path_regex_match() {
        let m = Matcher::PathRegex {
            pattern: r"^/users/\d+$".to_string(),
        };
        assert!(evaluate(&m, &ctx_with_path("/users/42")));
        assert!(!evaluate(&m, &ctx_with_path("/users/abc")));
    }

    // ── All / Any ──

    #[test]
    fn all_requires_every_matcher() {
        let m = Matcher::All {
            matchers: vec![
                Matcher::PathPrefix {
                    prefix: "/api".to_string(),
                },
                Matcher::RemoteIp {
                    ranges: vec!["10.0.0.0/8".to_string()],
                },
            ],
        };
        assert!(evaluate(&m, &ctx_with_path("/api/test")));
        assert!(!evaluate(&m, &ctx_with_path("/web/test")));
    }

    #[test]
    fn any_needs_one_matcher() {
        let m = Matcher::Any {
            matchers: vec![
                Matcher::PathPrefix {
                    prefix: "/api".to_string(),
                },
                Matcher::PathPrefix {
                    prefix: "/web".to_string(),
                },
            ],
        };
        assert!(evaluate(&m, &ctx_with_path("/api/test")));
        assert!(evaluate(&m, &ctx_with_path("/web/test")));
        assert!(!evaluate(&m, &ctx_with_path("/other")));
    }

    // ── Expression ──

    #[test]
    fn expr_path_starts_with() {
        let ctx = ctx_with_path("/api/v2/users");
        assert!(evaluate_expression(r#"path.startsWith("/api")"#, &ctx));
        assert!(!evaluate_expression(r#"path.startsWith("/web")"#, &ctx));
    }

    #[test]
    fn expr_path_matches() {
        let ctx = ctx_with_path("/users/42");
        assert!(evaluate_expression(r#"path.matches("^/users/\d+$")"#, &ctx));
    }

    #[test]
    fn expr_method_eq() {
        let ctx = ctx_with_path("/");
        assert!(evaluate_expression(r#"method == "GET""#, &ctx));
        assert!(!evaluate_expression(r#"method == "POST""#, &ctx));
    }

    #[test]
    fn expr_host_eq() {
        let ctx = ctx_with_path("/");
        assert!(evaluate_expression(r#"host == "example.com""#, &ctx));
    }

    #[test]
    fn expr_client_ip_in() {
        let ctx = ctx_with_path("/");
        assert!(evaluate_expression(
            r#"client_ip in "192.168.1.0/24""#,
            &ctx
        ));
        assert!(!evaluate_expression(
            r#"client_ip in "172.16.0.0/12""#,
            &ctx
        ));
    }

    #[test]
    fn expr_remote_ip_in() {
        let ctx = ctx_with_path("/");
        assert!(evaluate_expression(r#"remote_ip in "10.0.0.0/8""#, &ctx));
    }

    #[test]
    fn expr_negation() {
        let ctx = ctx_with_path("/");
        assert!(evaluate_expression(r#"!method == "POST""#, &ctx));
    }

    #[test]
    fn expr_and() {
        let ctx = ctx_with_path("/api/v1");
        assert!(evaluate_expression(
            r#"method == "GET" && path.startsWith("/api")"#,
            &ctx
        ));
        assert!(!evaluate_expression(
            r#"method == "POST" && path.startsWith("/api")"#,
            &ctx
        ));
    }

    #[test]
    fn expr_or() {
        let ctx = ctx_with_path("/web/page");
        assert!(evaluate_expression(
            r#"path.startsWith("/api") || path.startsWith("/web")"#,
            &ctx
        ));
    }

    #[test]
    fn expr_header_match() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-tenant", "acme".parse().unwrap());
        let ctx = MatcherContext {
            path: "/",
            method: "GET",
            host: None,
            remote_ip: None,
            client_ip: None,
            headers: Some(&headers),
            query_string: None,
            scheme: None,
            vars: &EMPTY_VARS,
        };
        assert!(evaluate_expression(r#"header.x-tenant == "acme""#, &ctx));
        assert!(!evaluate_expression(r#"header.x-tenant == "other""#, &ctx));
    }

    #[test]
    fn expr_query_match() {
        let ctx = MatcherContext {
            path: "/",
            method: "GET",
            host: None,
            remote_ip: None,
            client_ip: None,
            headers: None,
            query_string: Some("version=2&debug=true"),
            scheme: None,
            vars: &EMPTY_VARS,
        };
        assert!(evaluate_expression(r#"query.version == "2""#, &ctx));
        assert!(!evaluate_expression(r#"query.version == "3""#, &ctx));
    }

    // ── NamedMatcher registry ──

    #[test]
    fn named_matcher_registry() {
        let mut reg = MatcherRegistry::new();
        reg.register(
            "internal".to_string(),
            vec![Matcher::RemoteIp {
                ranges: vec!["10.0.0.0/8".to_string()],
            }],
        );
        assert!(reg.get("internal").is_some());
        assert!(reg.get("external").is_none());
    }

    #[test]
    fn evaluate_named_matcher() {
        let mut reg = MatcherRegistry::new();
        reg.register(
            "api_only".to_string(),
            vec![Matcher::PathPrefix {
                prefix: "/api".to_string(),
            }],
        );
        let matchers = reg.get("api_only").unwrap();
        assert!(evaluate_all(matchers, &ctx_with_path("/api/users")));
        assert!(!evaluate_all(matchers, &ctx_with_path("/web/page")));
    }

    // ── Feature 69: File matcher ──

    #[test]
    fn file_matcher_finds_existing_file() {
        // Use Cargo.toml which exists at project root
        let m = Matcher::File {
            path: env!("CARGO_MANIFEST_DIR").to_string(),
            try_files: vec!["Cargo.toml".to_string()],
        };
        let ctx = ctx_with_path("/");
        assert!(evaluate(&m, &ctx));
    }

    #[test]
    fn file_matcher_no_match_nonexistent() {
        let m = Matcher::File {
            path: env!("CARGO_MANIFEST_DIR").to_string(),
            try_files: vec!["nonexistent_file_xyz.txt".to_string()],
        };
        let ctx = ctx_with_path("/");
        assert!(!evaluate(&m, &ctx));
    }

    // ── Feature 70: Protocol matcher ──

    #[test]
    fn protocol_matches_https() {
        let m = Matcher::Protocol {
            protocol: "https".to_string(),
        };
        let mut ctx = ctx_with_path("/");
        ctx.scheme = Some("https");
        assert!(evaluate(&m, &ctx));
    }

    #[test]
    fn protocol_no_match() {
        let m = Matcher::Protocol {
            protocol: "grpc".to_string(),
        };
        let mut ctx = ctx_with_path("/");
        ctx.scheme = Some("http");
        assert!(!evaluate(&m, &ctx));
    }

    #[test]
    fn protocol_none_scheme() {
        let m = Matcher::Protocol {
            protocol: "http".to_string(),
        };
        let ctx = ctx_with_path("/");
        assert!(!evaluate(&m, &ctx)); // scheme is None
    }

    // ── Feature 71: Var / VarRegex matchers ──

    #[test]
    fn var_exact_match() {
        let vars: HashMap<String, String> = [("env".to_string(), "production".to_string())].into();
        let m = Matcher::Var {
            name: "env".to_string(),
            value: "production".to_string(),
        };
        let mut ctx = ctx_with_path("/");
        ctx.vars = &vars;
        assert!(evaluate(&m, &ctx));
    }

    #[test]
    fn var_no_match() {
        let vars: HashMap<String, String> = [("env".to_string(), "staging".to_string())].into();
        let m = Matcher::Var {
            name: "env".to_string(),
            value: "production".to_string(),
        };
        let mut ctx = ctx_with_path("/");
        ctx.vars = &vars;
        assert!(!evaluate(&m, &ctx));
    }

    #[test]
    fn var_missing_key() {
        let m = Matcher::Var {
            name: "missing".to_string(),
            value: "any".to_string(),
        };
        let ctx = ctx_with_path("/");
        assert!(!evaluate(&m, &ctx));
    }

    #[test]
    fn var_regex_match() {
        let vars: HashMap<String, String> = [("version".to_string(), "v2.3.1".to_string())].into();
        let m = Matcher::VarRegex {
            name: "version".to_string(),
            pattern: r"^v\d+\.\d+\.\d+$".to_string(),
        };
        let mut ctx = ctx_with_path("/");
        ctx.vars = &vars;
        assert!(evaluate(&m, &ctx));
    }

    #[test]
    fn var_regex_no_match() {
        let vars: HashMap<String, String> = [("version".to_string(), "latest".to_string())].into();
        let m = Matcher::VarRegex {
            name: "version".to_string(),
            pattern: r"^v\d+\.\d+\.\d+$".to_string(),
        };
        let mut ctx = ctx_with_path("/");
        ctx.vars = &vars;
        assert!(!evaluate(&m, &ctx));
    }

    // ── Feature 72: HeaderRegex matcher ──

    #[test]
    fn header_regex_match() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("user-agent", "Mozilla/5.0 (X11; Linux)".parse().unwrap());
        let m = Matcher::HeaderRegex {
            name: "user-agent".to_string(),
            pattern: r"Mozilla/\d+".to_string(),
        };
        let ctx = MatcherContext {
            path: "/",
            method: "GET",
            host: None,
            remote_ip: None,
            client_ip: None,
            headers: Some(&headers),
            query_string: None,
            scheme: None,
            vars: &EMPTY_VARS,
        };
        assert!(evaluate(&m, &ctx));
    }

    #[test]
    fn header_regex_no_match() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("user-agent", "curl/7.68".parse().unwrap());
        let m = Matcher::HeaderRegex {
            name: "user-agent".to_string(),
            pattern: r"^Mozilla".to_string(),
        };
        let ctx = MatcherContext {
            path: "/",
            method: "GET",
            host: None,
            remote_ip: None,
            client_ip: None,
            headers: Some(&headers),
            query_string: None,
            scheme: None,
            vars: &EMPTY_VARS,
        };
        assert!(!evaluate(&m, &ctx));
    }
}
