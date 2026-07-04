//! Lynxfile — human-friendly DSL for gateway configuration.
//!
//! A simplified alternative to TOML/YAML/JSON for quick setups.
//! Inspired by Caddy's Caddyfile with gateway-specific semantics.
//!
//! ## Syntax
//!
//! ```text
//! # Global options
//! {
//!     proxy_port 8000
//!     admin_port 8001
//!     database_url "sqlite://lynxx.db?mode=rwc"
//! }
//!
//! # Service block: name { ... }
//! user-api {
//!     url http://localhost:3000
//!     retries 3
//!
//!     route /api/users/* {
//!         strip_path
//!         methods GET POST PUT DELETE
//!     }
//!
//!     plugin rate-limit {
//!         requests_per_second 100
//!         burst 200
//!     }
//!
//!     plugin cors {
//!         origins *
//!         methods GET POST
//!     }
//! }
//! ```
//!
//! The parser converts this DSL into a `GatewayConfig` struct, which is
//! then serialised to TOML for the rest of the system.

use crate::config::{GatewayConfig, GatewaySettings, PluginConfig, RouteConfig, ServiceConfig};
use std::collections::HashMap;

/// Parse a Lynxfile DSL string into a `GatewayConfig`.
pub fn parse_lynxfile(input: &str) -> Result<GatewayConfig, LynxfileError> {
    let mut parser = Parser::new(input);
    parser.parse()
}

struct Parser<'a> {
    input: &'a str,
    pos: usize,
    line: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum LynxfileError {
    #[error("line {line}: {msg}")]
    Parse { line: usize, msg: String },
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            pos: 0,
            line: 1,
        }
    }

    fn parse(&mut self) -> Result<GatewayConfig, LynxfileError> {
        let mut config = GatewayConfig::default();
        let mut services = Vec::new();
        let mut routes = Vec::new();
        let mut plugins = Vec::new();

        self.skip_whitespace_and_comments();

        while self.pos < self.input.len() {
            let token = self.peek_token();
            match token.as_deref() {
                Some("{") => {
                    // Global options block
                    self.advance_token(); // consume '{'
                    self.parse_global_block(&mut config.gateway)?;
                }
                Some(name) => {
                    let name = name.to_string();
                    self.advance_token();
                    self.skip_whitespace_and_comments();
                    self.expect("{")?;
                    self.parse_service_block(&name, &mut services, &mut routes, &mut plugins)?;
                }
                None => break,
            }
            self.skip_whitespace_and_comments();
        }

        config.services = services;
        config.routes = routes;
        config.plugins = plugins;
        Ok(config)
    }

    fn parse_global_block(&mut self, settings: &mut GatewaySettings) -> Result<(), LynxfileError> {
        loop {
            self.skip_whitespace_and_comments();
            let token = self.peek_token();
            match token.as_deref() {
                Some("}") => {
                    self.advance_token();
                    return Ok(());
                }
                Some("proxy_port") => {
                    self.advance_token();
                    settings.proxy_port = self.expect_u16()?;
                }
                Some("admin_port") => {
                    self.advance_token();
                    settings.admin_port = self.expect_u16()?;
                }
                Some("database_url") => {
                    self.advance_token();
                    settings.database_url = self.expect_string()?;
                }
                Some("seed_from_config") => {
                    self.advance_token();
                    settings.seed_from_config = true;
                }
                Some(other) => {
                    return Err(LynxfileError::Parse {
                        line: self.line,
                        msg: format!("unknown global option: {other}"),
                    });
                }
                None => {
                    return Err(LynxfileError::Parse {
                        line: self.line,
                        msg: "unexpected EOF in global block".into(),
                    });
                }
            }
        }
    }

    fn parse_service_block(
        &mut self,
        service_name: &str,
        services: &mut Vec<ServiceConfig>,
        routes: &mut Vec<RouteConfig>,
        plugins: &mut Vec<PluginConfig>,
    ) -> Result<(), LynxfileError> {
        let mut url = String::new();
        let mut retries = 3u32;
        let mut timeout = 5000u64;
        let mut hide_patterns = Vec::new();

        loop {
            self.skip_whitespace_and_comments();
            let token = self.peek_token();
            match token.as_deref() {
                Some("}") => {
                    self.advance_token();
                    break;
                }
                Some("url") => {
                    self.advance_token();
                    url = self.expect_string()?;
                }
                Some("retries") => {
                    self.advance_token();
                    retries = self.expect_u32()?;
                }
                Some("connect_timeout_ms") => {
                    self.advance_token();
                    timeout = self.expect_u64()?;
                }
                Some("hide_pattern") => {
                    self.advance_token();
                    hide_patterns.push(self.expect_string()?);
                }
                Some("route") => {
                    self.advance_token();
                    let path = self.expect_string()?;
                    self.expect("{")?;
                    let route = self.parse_route_block(&path, service_name)?;
                    routes.push(route);
                }
                Some("plugin") => {
                    self.advance_token();
                    let plugin_name = self.expect_string()?;
                    self.expect("{")?;
                    let plugin = self.parse_plugin_block(&plugin_name)?;
                    plugins.push(plugin);
                }
                Some(other) => {
                    return Err(LynxfileError::Parse {
                        line: self.line,
                        msg: format!("unknown service directive: {other}"),
                    });
                }
                None => {
                    return Err(LynxfileError::Parse {
                        line: self.line,
                        msg: "unexpected EOF in service block".into(),
                    });
                }
            }
        }

        services.push(ServiceConfig {
            name: service_name.to_string(),
            url,
            retries,
            connect_timeout_ms: timeout,
            service_type: None,
            document_root: None,
            index_file: None,
            spa_fallback: None,
            hide_patterns,
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

        Ok(())
    }

    fn parse_route_block(
        &mut self,
        path: &str,
        service: &str,
    ) -> Result<RouteConfig, LynxfileError> {
        let mut methods = Vec::new();
        let mut hosts = Vec::new();
        let mut strip_path = false;

        loop {
            self.skip_whitespace_and_comments();
            let token = self.peek_token();
            match token.as_deref() {
                Some("}") => {
                    self.advance_token();
                    break;
                }
                Some("strip_path") => {
                    self.advance_token();
                    strip_path = true;
                }
                Some("methods") => {
                    self.advance_token();
                    methods = self.collect_line_tokens();
                }
                Some("hosts") => {
                    self.advance_token();
                    hosts = self.collect_line_tokens();
                }
                Some(other) => {
                    return Err(LynxfileError::Parse {
                        line: self.line,
                        msg: format!("unknown route directive: {other}"),
                    });
                }
                None => {
                    return Err(LynxfileError::Parse {
                        line: self.line,
                        msg: "unexpected EOF in route block".into(),
                    });
                }
            }
        }

        Ok(RouteConfig {
            paths: vec![path.to_string()],
            methods,
            hosts,
            service: service.to_string(),
            strip_path,
            id_tag: None,
            vars: HashMap::new(),
            invoke: None,
            literal_order: false,
        })
    }

    fn parse_plugin_block(&mut self, name: &str) -> Result<PluginConfig, LynxfileError> {
        let mut map = serde_json::Map::new();

        loop {
            self.skip_whitespace_and_comments();
            let token = self.peek_token();
            match token.as_deref() {
                Some("}") => {
                    self.advance_token();
                    break;
                }
                Some(key) => {
                    let key = key.to_string();
                    self.advance_token();
                    let value = self.expect_string()?;

                    // Try parsing as number, then bool, then string
                    if let Ok(n) = value.parse::<i64>() {
                        map.insert(key, serde_json::Value::Number(n.into()));
                    } else if let Ok(b) = value.parse::<bool>() {
                        map.insert(key, serde_json::Value::Bool(b));
                    } else {
                        map.insert(key, serde_json::Value::String(value));
                    }
                }
                None => {
                    return Err(LynxfileError::Parse {
                        line: self.line,
                        msg: "unexpected EOF in plugin block".into(),
                    });
                }
            }
        }

        Ok(PluginConfig {
            name: name.to_string(),
            enabled: true,
            config: serde_json::Value::Object(map),
            id_tag: None,
        })
    }

    // --- Lexer helpers ---

    fn skip_whitespace_and_comments(&mut self) {
        let bytes = self.input.as_bytes();
        while self.pos < bytes.len() {
            match bytes[self.pos] {
                b' ' | b'\t' | b'\r' => self.pos += 1,
                b'\n' => {
                    self.pos += 1;
                    self.line += 1;
                }
                b'#' => {
                    // Skip to end of line
                    while self.pos < bytes.len() && bytes[self.pos] != b'\n' {
                        self.pos += 1;
                    }
                }
                _ => break,
            }
        }
    }

    fn peek_token(&self) -> Option<String> {
        let bytes = self.input.as_bytes();
        let mut pos = self.pos;
        if pos >= bytes.len() {
            return None;
        }

        // Braces are single-char tokens
        if bytes[pos] == b'{' || bytes[pos] == b'}' {
            return Some(String::from(bytes[pos] as char));
        }

        // Quoted string
        if bytes[pos] == b'"' {
            pos += 1;
            let start = pos;
            while pos < bytes.len() && bytes[pos] != b'"' {
                pos += 1;
            }
            return Some(String::from_utf8_lossy(&bytes[start..pos]).to_string());
        }

        // Bare word
        let start = pos;
        while pos < bytes.len() && !matches!(bytes[pos], b' ' | b'\t' | b'\r' | b'\n' | b'{' | b'}')
        {
            pos += 1;
        }
        if pos > start {
            Some(String::from_utf8_lossy(&bytes[start..pos]).to_string())
        } else {
            None
        }
    }

    fn advance_token(&mut self) {
        let bytes = self.input.as_bytes();
        if self.pos >= bytes.len() {
            return;
        }

        if bytes[self.pos] == b'{' || bytes[self.pos] == b'}' {
            self.pos += 1;
            return;
        }

        if bytes[self.pos] == b'"' {
            self.pos += 1;
            while self.pos < bytes.len() && bytes[self.pos] != b'"' {
                self.pos += 1;
            }
            if self.pos < bytes.len() {
                self.pos += 1; // closing quote
            }
            return;
        }

        while self.pos < bytes.len()
            && !matches!(bytes[self.pos], b' ' | b'\t' | b'\r' | b'\n' | b'{' | b'}')
        {
            self.pos += 1;
        }
    }

    fn expect(&mut self, expected: &str) -> Result<(), LynxfileError> {
        self.skip_whitespace_and_comments();
        let token = self.peek_token();
        if token.as_deref() == Some(expected) {
            self.advance_token();
            Ok(())
        } else {
            Err(LynxfileError::Parse {
                line: self.line,
                msg: format!("expected '{expected}', got {:?}", token),
            })
        }
    }

    fn expect_string(&mut self) -> Result<String, LynxfileError> {
        self.skip_whitespace_and_comments();
        match self.peek_token() {
            Some(s) if s != "{" && s != "}" => {
                self.advance_token();
                Ok(s)
            }
            other => Err(LynxfileError::Parse {
                line: self.line,
                msg: format!("expected string, got {:?}", other),
            }),
        }
    }

    fn expect_u16(&mut self) -> Result<u16, LynxfileError> {
        let s = self.expect_string()?;
        s.parse().map_err(|_| LynxfileError::Parse {
            line: self.line,
            msg: format!("expected u16, got '{s}'"),
        })
    }

    fn expect_u32(&mut self) -> Result<u32, LynxfileError> {
        let s = self.expect_string()?;
        s.parse().map_err(|_| LynxfileError::Parse {
            line: self.line,
            msg: format!("expected u32, got '{s}'"),
        })
    }

    fn expect_u64(&mut self) -> Result<u64, LynxfileError> {
        let s = self.expect_string()?;
        s.parse().map_err(|_| LynxfileError::Parse {
            line: self.line,
            msg: format!("expected u64, got '{s}'"),
        })
    }

    fn collect_line_tokens(&mut self) -> Vec<String> {
        let mut tokens = Vec::new();
        loop {
            self.skip_inline_whitespace();
            if self.pos >= self.input.len() {
                break;
            }
            let ch = self.input.as_bytes()[self.pos];
            if ch == b'\n' || ch == b'#' || ch == b'{' || ch == b'}' {
                break;
            }
            if let Some(t) = self.peek_token() {
                self.advance_token();
                tokens.push(t);
            } else {
                break;
            }
        }
        tokens
    }

    fn skip_inline_whitespace(&mut self) {
        let bytes = self.input.as_bytes();
        while self.pos < bytes.len() && matches!(bytes[self.pos], b' ' | b'\t') {
            self.pos += 1;
        }
    }
}

/// Convert a Lynxfile to TOML for writing back.
pub fn lynxfile_to_toml(config: &GatewayConfig) -> Result<String, LynxfileError> {
    toml::to_string_pretty(config).map_err(|e| LynxfileError::Parse {
        line: 0,
        msg: format!("toml serialization: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty() {
        let config = parse_lynxfile("").unwrap();
        assert!(config.services.is_empty());
    }

    #[test]
    fn parse_global_block() {
        let input = r#"
{
    proxy_port 28080
    admin_port 28081
}
"#;
        let config = parse_lynxfile(input).unwrap();
        assert_eq!(config.gateway.proxy_port, 28080);
        assert_eq!(config.gateway.admin_port, 28081);
    }

    #[test]
    fn parse_service_with_route() {
        let input = r#"
my-api {
    url http://localhost:3000
    retries 5

    route /api/* {
        strip_path
        methods GET POST
    }
}
"#;
        let config = parse_lynxfile(input).unwrap();
        assert_eq!(config.services.len(), 1);
        assert_eq!(config.services[0].name, "my-api");
        assert_eq!(config.services[0].url, "http://localhost:3000");
        assert_eq!(config.services[0].retries, 5);
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.routes[0].paths, vec!["/api/*"]);
        assert!(config.routes[0].strip_path);
        assert_eq!(config.routes[0].methods, vec!["GET", "POST"]);
    }

    #[test]
    fn parse_plugin() {
        let input = r#"
api {
    url http://localhost:3000

    plugin rate-limit {
        requests_per_second 100
        burst 200
    }
}
"#;
        let config = parse_lynxfile(input).unwrap();
        assert_eq!(config.plugins.len(), 1);
        assert_eq!(config.plugins[0].name, "rate-limit");
        assert_eq!(
            config.plugins[0].config.get("requests_per_second"),
            Some(&serde_json::Value::Number(100.into()))
        );
    }

    #[test]
    fn parse_comments() {
        let input = r#"
# This is a comment
{
    proxy_port 8080 # inline comment
}
"#;
        let config = parse_lynxfile(input).unwrap();
        assert_eq!(config.gateway.proxy_port, 8080);
    }
}
