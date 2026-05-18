//! Convert third-party config formats into a [`GatewayConfig`].
//!
//! Currently supports a simplified Nginx `server { }` block via
//! [`NginxAdapter`]. New formats (HAProxy, Envoy, Caddy, ...) can be
//! added by implementing the [`ConfigAdapter`] trait.

use crate::config::{GatewayConfig, RouteConfig, ServiceConfig};

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Generic adapter: convert an opaque config string into a `GatewayConfig`.
pub trait ConfigAdapter {
    fn name(&self) -> &str;
    fn convert(&self, input: &str) -> Result<GatewayConfig, String>;
}

// ---------------------------------------------------------------------------
// Nginx adapter
// ---------------------------------------------------------------------------

pub struct NginxAdapter;

impl NginxAdapter {
    /// Parse an Nginx-style config string and produce a [`GatewayConfig`].
    pub fn convert(input: &str) -> Result<GatewayConfig, String> {
        let tokens = tokenize(input);
        let blocks = parse_top_level(&tokens)?;

        let mut config = GatewayConfig::default();
        let mut upstreams: Vec<Upstream> = Vec::new();

        for block in &blocks {
            match block {
                TopLevel::Upstream(u) => upstreams.push(u.clone()),
                TopLevel::Server(s) => {
                    apply_server(s, &upstreams, &mut config)?;
                }
            }
        }

        Ok(config)
    }
}

impl ConfigAdapter for NginxAdapter {
    fn name(&self) -> &str {
        "nginx"
    }

    fn convert(&self, input: &str) -> Result<GatewayConfig, String> {
        NginxAdapter::convert(input)
    }
}

// ---------------------------------------------------------------------------
// Internal AST
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Upstream {
    name: String,
    servers: Vec<String>,
}

#[derive(Debug, Clone)]
struct ServerBlock {
    directives: Vec<Directive>,
    locations: Vec<LocationBlock>,
}

#[derive(Debug, Clone)]
struct LocationBlock {
    path: String,
    directives: Vec<Directive>,
}

#[derive(Debug, Clone)]
struct Directive {
    key: String,
    values: Vec<String>,
}

#[derive(Debug, Clone)]
enum TopLevel {
    Server(ServerBlock),
    Upstream(Upstream),
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

/// Token types produced by the lexer.
#[derive(Debug, Clone, PartialEq)]
enum Token {
    Word(String),
    OpenBrace,
    CloseBrace,
    Semi,
}

/// Tokenize Nginx config text into a flat stream of [`Token`]s.
///
/// * `#` comments are stripped (everything from `#` to end-of-line).
/// * Braces (`{`, `}`) and semicolons (`;`) are individual tokens.
/// * Everything else is split on whitespace into `Word` tokens.
fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(&ch) = chars.peek() {
        match ch {
            '#' => {
                // Skip until end of line.
                while let Some(&c) = chars.peek() {
                    chars.next();
                    if c == '\n' {
                        break;
                    }
                }
            }
            '{' => {
                tokens.push(Token::OpenBrace);
                chars.next();
            }
            '}' => {
                tokens.push(Token::CloseBrace);
                chars.next();
            }
            ';' => {
                tokens.push(Token::Semi);
                chars.next();
            }
            c if c.is_whitespace() => {
                chars.next();
            }
            _ => {
                let mut word = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() || c == '{' || c == '}' || c == ';' || c == '#' {
                        break;
                    }
                    word.push(c);
                    chars.next();
                }
                if !word.is_empty() {
                    tokens.push(Token::Word(word));
                }
            }
        }
    }

    tokens
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Cursor into the token stream.
struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [Token]) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<&Token> {
        let tok = self.tokens.get(self.pos);
        if tok.is_some() {
            self.pos += 1;
        }
        tok
    }

    fn expect_word(&mut self) -> Result<String, String> {
        match self.next() {
            Some(Token::Word(w)) => Ok(w.clone()),
            other => Err(format!("expected word, got {other:?}")),
        }
    }

    fn expect(&mut self, expected: &Token) -> Result<(), String> {
        match self.next() {
            Some(tok) if tok == expected => Ok(()),
            other => Err(format!("expected {expected:?}, got {other:?}")),
        }
    }
}

/// Parse all top-level blocks (`server { }` and `upstream <name> { }`).
fn parse_top_level(tokens: &[Token]) -> Result<Vec<TopLevel>, String> {
    let mut p = Parser::new(tokens);
    let mut blocks = Vec::new();

    while let Some(tok) = p.peek() {
        match tok {
            Token::Word(w) if w == "server" => {
                p.next(); // consume "server"
                let server = parse_server_block(&mut p)?;
                blocks.push(TopLevel::Server(server));
            }
            Token::Word(w) if w == "upstream" => {
                p.next(); // consume "upstream"
                let upstream = parse_upstream_block(&mut p)?;
                blocks.push(TopLevel::Upstream(upstream));
            }
            _ => {
                // Skip unknown top-level tokens (e.g. bare directives
                // outside of blocks).
                p.next();
            }
        }
    }

    Ok(blocks)
}

/// Parse `{ ... }` after `server`.
fn parse_server_block(p: &mut Parser) -> Result<ServerBlock, String> {
    p.expect(&Token::OpenBrace)?;

    let mut directives = Vec::new();
    let mut locations = Vec::new();

    loop {
        match p.peek() {
            None => return Err("unexpected EOF inside server block".into()),
            Some(Token::CloseBrace) => {
                p.next();
                break;
            }
            Some(Token::Word(w)) if w == "location" => {
                p.next(); // consume "location"
                let loc = parse_location_block(p)?;
                locations.push(loc);
            }
            Some(Token::Word(_)) => {
                let dir = parse_directive(p)?;
                directives.push(dir);
            }
            Some(tok) => {
                return Err(format!("unexpected token in server block: {tok:?}"));
            }
        }
    }

    Ok(ServerBlock {
        directives,
        locations,
    })
}

/// Parse `<path> { ... }` after `location`.
fn parse_location_block(p: &mut Parser) -> Result<LocationBlock, String> {
    let path = p.expect_word()?;
    p.expect(&Token::OpenBrace)?;

    let mut directives = Vec::new();

    loop {
        match p.peek() {
            None => return Err("unexpected EOF inside location block".into()),
            Some(Token::CloseBrace) => {
                p.next();
                break;
            }
            Some(Token::Word(_)) => {
                let dir = parse_directive(p)?;
                directives.push(dir);
            }
            Some(tok) => {
                return Err(format!("unexpected token in location block: {tok:?}"));
            }
        }
    }

    Ok(LocationBlock { path, directives })
}

/// Parse `<name> { server <addr>; ... }` after `upstream`.
fn parse_upstream_block(p: &mut Parser) -> Result<Upstream, String> {
    let name = p.expect_word()?;
    p.expect(&Token::OpenBrace)?;

    let mut servers = Vec::new();

    loop {
        match p.peek() {
            None => return Err("unexpected EOF inside upstream block".into()),
            Some(Token::CloseBrace) => {
                p.next();
                break;
            }
            Some(Token::Word(w)) if w == "server" => {
                p.next(); // consume "server"
                let addr = p.expect_word()?;
                p.expect(&Token::Semi)?;
                servers.push(addr);
            }
            Some(Token::Word(_)) => {
                // Skip unknown upstream directives.
                parse_directive(p)?;
            }
            Some(tok) => {
                return Err(format!("unexpected token in upstream block: {tok:?}"));
            }
        }
    }

    Ok(Upstream { name, servers })
}

/// Parse a simple `key value1 value2 ... ;` directive.
fn parse_directive(p: &mut Parser) -> Result<Directive, String> {
    let key = p.expect_word()?;
    let mut values = Vec::new();

    loop {
        match p.peek() {
            None => return Err(format!("unexpected EOF after directive `{key}`")),
            Some(Token::Semi) => {
                p.next();
                break;
            }
            Some(Token::Word(w)) => {
                values.push(w.clone());
                p.next();
            }
            Some(Token::OpenBrace) | Some(Token::CloseBrace) => {
                // End of directive values without a semicolon — the
                // caller will handle the brace.
                break;
            }
        }
    }

    Ok(Directive { key, values })
}

// ---------------------------------------------------------------------------
// Semantic mapping: AST -> GatewayConfig
// ---------------------------------------------------------------------------

fn apply_server(
    server: &ServerBlock,
    upstreams: &[Upstream],
    config: &mut GatewayConfig,
) -> Result<(), String> {
    let mut server_name: Option<String> = None;

    for dir in &server.directives {
        match dir.key.as_str() {
            "listen" => {
                if let Some(port_str) = dir.values.first() {
                    // `listen 8080;` or `listen 443 ssl;`
                    let port_str = port_str.trim_end_matches(';');
                    if let Ok(port) = port_str.parse::<u16>() {
                        config.gateway.proxy_port = port;
                    }
                }
            }
            "server_name" => {
                if let Some(name) = dir.values.first() {
                    server_name = Some(name.clone());
                }
            }
            "ssl_certificate" => {
                if let Some(path) = dir.values.first() {
                    config.gateway.tls.cert_path = path.clone();
                    config.gateway.tls.enabled = true;
                }
            }
            "ssl_certificate_key" => {
                if let Some(path) = dir.values.first() {
                    config.gateway.tls.key_path = path.clone();
                    config.gateway.tls.enabled = true;
                }
            }
            "proxy_set_header" => {
                tracing::warn!("ignoring proxy_set_header directive (not supported in conversion)");
            }
            _ => {
                // Unknown server-level directive — silently skip.
            }
        }
    }

    // Process each `location` inside the server block.
    for loc in &server.locations {
        let mut proxy_pass: Option<String> = None;
        let mut root_dir: Option<String> = None;
        let mut connect_timeout_ms: Option<u64> = None;

        for dir in &loc.directives {
            match dir.key.as_str() {
                "proxy_pass" => {
                    if let Some(url) = dir.values.first() {
                        proxy_pass = Some(url.clone());
                    }
                }
                "root" => {
                    if let Some(dir_path) = dir.values.first() {
                        root_dir = Some(dir_path.clone());
                    }
                }
                "proxy_connect_timeout" => {
                    if let Some(val) = dir.values.first() {
                        connect_timeout_ms = Some(parse_duration_ms(val));
                    }
                }
                "proxy_set_header" => {
                    tracing::warn!(
                        "ignoring proxy_set_header in location {} (not supported)",
                        loc.path
                    );
                }
                _ => {}
            }
        }

        if let Some(url) = proxy_pass {
            // Resolve upstream references: if `proxy_pass http://my_upstream`
            // and we have an upstream block named `my_upstream`, create a
            // service per upstream server entry.
            let upstream_name = extract_upstream_name(&url);
            let resolved_upstream = upstream_name
                .as_deref()
                .and_then(|n| upstreams.iter().find(|u| u.name == n));

            let service_name = make_service_name(&loc.path);

            if let Some(upstream) = resolved_upstream {
                // Build one service whose URL is the first upstream server.
                // Additional servers are noted but Lynxx targets would need
                // the admin API; we pick the first for the config file.
                let first = upstream.servers.first().cloned().unwrap_or_default();
                let svc_url = format!("http://{first}");
                let svc = ServiceConfig {
                    name: service_name.clone(),
                    url: svc_url,
                    retries: 3,
                    connect_timeout_ms: connect_timeout_ms.unwrap_or(5000),
                    service_type: None,
                    document_root: None,
                    index_file: None,
                    spa_fallback: None,
                    id_tag: None,
                    stream_timeout_secs: 0,
                    stream_close_delay_secs: 0,
                    lb_try_duration_ms: 0,
                    lb_try_interval_ms: 250,
                    lb_retry_match: Vec::new(),
                    request_buffer_size: 0,
                    response_buffer_size: 0,
                    flush_interval_ms: -1,
                    pass_host_header: false,
                    root: String::new(),
                };
                config.services.push(svc);
            } else {
                let svc = ServiceConfig {
                    name: service_name.clone(),
                    url: url.clone(),
                    retries: 3,
                    connect_timeout_ms: connect_timeout_ms.unwrap_or(5000),
                    service_type: None,
                    document_root: None,
                    index_file: None,
                    spa_fallback: None,
                    id_tag: None,
                    stream_timeout_secs: 0,
                    stream_close_delay_secs: 0,
                    lb_try_duration_ms: 0,
                    lb_try_interval_ms: 250,
                    lb_retry_match: Vec::new(),
                    request_buffer_size: 0,
                    response_buffer_size: 0,
                    flush_interval_ms: -1,
                    pass_host_header: false,
                    root: String::new(),
                };
                config.services.push(svc);
            }

            let mut hosts = Vec::new();
            if let Some(ref h) = server_name {
                hosts.push(h.clone());
            }
            config.routes.push(RouteConfig {
                paths: vec![loc.path.clone()],
                methods: Vec::new(),
                hosts,
                service: service_name,
                strip_path: false,
                id_tag: None,
                vars: std::collections::HashMap::new(),
                invoke: None,
                literal_order: false,
            });
        } else if let Some(doc_root) = root_dir {
            let service_name = make_service_name(&loc.path);
            config.services.push(ServiceConfig {
                name: service_name.clone(),
                url: String::new(),
                retries: 3,
                connect_timeout_ms: connect_timeout_ms.unwrap_or(5000),
                service_type: Some("static".into()),
                document_root: Some(doc_root),
                index_file: None,
                spa_fallback: None,
                id_tag: None,
                stream_timeout_secs: 0,
                stream_close_delay_secs: 0,
                lb_try_duration_ms: 0,
                lb_try_interval_ms: 250,
                lb_retry_match: Vec::new(),
                request_buffer_size: 0,
                response_buffer_size: 0,
                flush_interval_ms: -1,
                pass_host_header: false,
                root: String::new(),
            });

            let mut hosts = Vec::new();
            if let Some(ref h) = server_name {
                hosts.push(h.clone());
            }
            config.routes.push(RouteConfig {
                paths: vec![loc.path.clone()],
                methods: Vec::new(),
                hosts,
                service: service_name,
                strip_path: false,
                id_tag: None,
                vars: std::collections::HashMap::new(),
                invoke: None,
                literal_order: false,
            });
        }
    }

    Ok(())
}

/// Try to extract an upstream name from a proxy_pass URL.
/// e.g. `http://my_backend` -> Some("my_backend")
///       `http://127.0.0.1:3000` -> None
fn extract_upstream_name(url: &str) -> Option<String> {
    let host = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    // If the host portion contains a dot or colon it is a real address, not
    // an Nginx upstream reference.
    let host = host.split('/').next().unwrap_or(host);
    if host.contains('.') || host.contains(':') {
        None
    } else {
        Some(host.to_string())
    }
}

/// Derive a Lynxx service name from a location path.
fn make_service_name(path: &str) -> String {
    let clean = path.trim_matches('/').replace('/', "-");
    if clean.is_empty() {
        "default-service".into()
    } else {
        format!("{clean}-service")
    }
}

/// Parse an Nginx duration value into milliseconds.
///
/// Supported suffixes: `s` (seconds), `ms` (milliseconds). A bare number
/// is treated as seconds (Nginx default).
fn parse_duration_ms(val: &str) -> u64 {
    if let Some(stripped) = val.strip_suffix("ms") {
        stripped.parse::<u64>().unwrap_or(5000)
    } else if let Some(stripped) = val.strip_suffix('s') {
        stripped.parse::<u64>().map(|s| s * 1000).unwrap_or(5000)
    } else {
        // Bare number — treat as seconds.
        val.parse::<u64>().map(|s| s * 1000).unwrap_or(5000)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nginx_basic_proxy() {
        let input = r#"
            server {
                location / {
                    proxy_pass http://127.0.0.1:3000;
                }
            }
        "#;
        let cfg = NginxAdapter::convert(input).unwrap();
        assert_eq!(cfg.services.len(), 1);
        assert_eq!(cfg.services[0].url, "http://127.0.0.1:3000");
        assert_eq!(cfg.routes.len(), 1);
        assert_eq!(cfg.routes[0].paths, vec!["/"]);
        assert_eq!(cfg.routes[0].service, "default-service");
    }

    #[test]
    fn nginx_multiple_locations() {
        let input = r#"
            server {
                location /api {
                    proxy_pass http://127.0.0.1:3000;
                }
                location /web {
                    proxy_pass http://127.0.0.1:4000;
                }
            }
        "#;
        let cfg = NginxAdapter::convert(input).unwrap();
        assert_eq!(cfg.services.len(), 2);
        assert_eq!(cfg.routes.len(), 2);
        assert_eq!(cfg.services[0].name, "api-service");
        assert_eq!(cfg.services[1].name, "web-service");
    }

    #[test]
    fn nginx_with_listen_port() {
        let input = r#"
            server {
                listen 9090;
                location / {
                    proxy_pass http://127.0.0.1:3000;
                }
            }
        "#;
        let cfg = NginxAdapter::convert(input).unwrap();
        assert_eq!(cfg.gateway.proxy_port, 9090);
    }

    #[test]
    fn nginx_with_server_name() {
        let input = r#"
            server {
                server_name api.example.com;
                location /v1 {
                    proxy_pass http://127.0.0.1:3000;
                }
            }
        "#;
        let cfg = NginxAdapter::convert(input).unwrap();
        assert_eq!(cfg.routes[0].hosts, vec!["api.example.com"]);
    }

    #[test]
    fn nginx_ssl() {
        let input = r#"
            server {
                listen 443;
                ssl_certificate /etc/ssl/cert.pem;
                ssl_certificate_key /etc/ssl/key.pem;
                location / {
                    proxy_pass http://127.0.0.1:3000;
                }
            }
        "#;
        let cfg = NginxAdapter::convert(input).unwrap();
        assert!(cfg.gateway.tls.enabled);
        assert_eq!(cfg.gateway.tls.cert_path, "/etc/ssl/cert.pem");
        assert_eq!(cfg.gateway.tls.key_path, "/etc/ssl/key.pem");
        assert_eq!(cfg.gateway.proxy_port, 443);
    }

    #[test]
    fn nginx_static_root() {
        let input = r#"
            server {
                location /assets {
                    root /var/www/html;
                }
            }
        "#;
        let cfg = NginxAdapter::convert(input).unwrap();
        assert_eq!(cfg.services.len(), 1);
        assert_eq!(cfg.services[0].service_type.as_deref(), Some("static"));
        assert_eq!(
            cfg.services[0].document_root.as_deref(),
            Some("/var/www/html")
        );
        assert_eq!(cfg.routes[0].paths, vec!["/assets"]);
    }

    #[test]
    fn nginx_upstream_block() {
        let input = r#"
            upstream backend {
                server 10.0.0.1:8080;
                server 10.0.0.2:8080;
            }
            server {
                location /api {
                    proxy_pass http://backend;
                }
            }
        "#;
        let cfg = NginxAdapter::convert(input).unwrap();
        assert_eq!(cfg.services.len(), 1);
        // The first upstream server is used as the service URL.
        assert_eq!(cfg.services[0].url, "http://10.0.0.1:8080");
        assert_eq!(cfg.services[0].name, "api-service");
    }

    #[test]
    fn nginx_connect_timeout() {
        let input = r#"
            server {
                location / {
                    proxy_pass http://127.0.0.1:3000;
                    proxy_connect_timeout 30s;
                }
            }
        "#;
        let cfg = NginxAdapter::convert(input).unwrap();
        assert_eq!(cfg.services[0].connect_timeout_ms, 30_000);
    }

    #[test]
    fn nginx_comments_stripped() {
        let input = r#"
            # This is a comment
            server {
                # listen on default port
                listen 8080; # inline comment
                location / {
                    proxy_pass http://127.0.0.1:3000;
                }
            }
        "#;
        let cfg = NginxAdapter::convert(input).unwrap();
        assert_eq!(cfg.gateway.proxy_port, 8080);
        assert_eq!(cfg.services.len(), 1);
    }

    #[test]
    fn nginx_empty_input() {
        let cfg = NginxAdapter::convert("").unwrap();
        assert_eq!(cfg.services.len(), 0);
        assert_eq!(cfg.routes.len(), 0);
        // Proxy port falls back to GatewayConfig default.
        assert_eq!(cfg.gateway.proxy_port, 8000);
    }

    #[test]
    fn adapter_trait() {
        let adapter = NginxAdapter;
        assert_eq!(adapter.name(), "nginx");

        let input = r#"
            server {
                location / {
                    proxy_pass http://127.0.0.1:3000;
                }
            }
        "#;
        let cfg = ConfigAdapter::convert(&adapter, input).unwrap();
        assert_eq!(cfg.services.len(), 1);
    }

    #[test]
    fn nginx_timeout_ms_suffix() {
        let input = r#"
            server {
                location / {
                    proxy_pass http://127.0.0.1:3000;
                    proxy_connect_timeout 500ms;
                }
            }
        "#;
        let cfg = NginxAdapter::convert(input).unwrap();
        assert_eq!(cfg.services[0].connect_timeout_ms, 500);
    }

    #[test]
    fn nginx_multiple_upstream_blocks() {
        let input = r#"
            upstream api_servers {
                server 10.0.0.1:8080;
            }
            upstream web_servers {
                server 10.0.0.2:9090;
            }
            server {
                location /api {
                    proxy_pass http://api_servers;
                }
                location /web {
                    proxy_pass http://web_servers;
                }
            }
        "#;
        let cfg = NginxAdapter::convert(input).unwrap();
        assert_eq!(cfg.services.len(), 2);
        assert_eq!(cfg.services[0].url, "http://10.0.0.1:8080");
        assert_eq!(cfg.services[1].url, "http://10.0.0.2:9090");
    }
}
