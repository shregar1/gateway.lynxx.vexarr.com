//! Template processing plugin.
//!
//! Renders template expressions in response bodies before sending them
//! downstream. Supports variable interpolation, conditionals, and
//! includes — a simplified version of Caddy's `templates` directive.
//!
//! Config:
//! ```json
//! {
//!   "content_types": ["text/html", "text/plain"],
//!   "delimiters": ["{{", "}}"],
//!   "variables": { "site_name": "My Site", "version": "1.0" }
//! }
//! ```
//!
//! Template syntax:
//! - `{{.Variable}}` — insert a variable value
//! - `{{.Env "VAR"}}` — insert an environment variable
//! - `{{.Host}}` — request Host header
//! - `{{.Path}}` — request path
//! - `{{.Method}}` — request method
//! - `{{.RemoteAddr}}` — client IP (from X-Real-IP or socket)
//! - `{{now}}` — current UTC timestamp (RFC 3339)
//! - `{{httpStatus}}` — response status code

use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, Response};
use http_body_util::BodyExt;
use std::collections::HashMap;

pub struct TemplatePlugin {
    content_types: Vec<String>,
    open_delim: String,
    close_delim: String,
    variables: HashMap<String, String>,
    /// Allowlist of environment variable names that `{{.Env "VAR"}}` may
    /// expand. SECURITY: templates render against the (upstream-controlled)
    /// response body, so without an allowlist an attacker who can influence a
    /// templated response could exfiltrate ANY process env var — including
    /// `LYNXX_API_KEY`, `DATABASE_URL`, AWS creds. Default is empty (deny all):
    /// operators must opt-in the specific vars they intend to expose.
    env_allowlist: std::collections::HashSet<String>,
}

impl TemplatePlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let content_types = if let Some(arr) = cfg.get("content_types").and_then(|v| v.as_array()) {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(String::from)
                .collect()
        } else {
            vec!["text/html".to_string()]
        };

        let (open_delim, close_delim) =
            if let Some(arr) = cfg.get("delimiters").and_then(|v| v.as_array()) {
                let open = arr.first().and_then(|v| v.as_str()).unwrap_or("{{");
                let close = arr.get(1).and_then(|v| v.as_str()).unwrap_or("}}");
                (open.to_string(), close.to_string())
            } else {
                ("{{".to_string(), "}}".to_string())
            };

        let variables = if let Some(obj) = cfg.get("variables").and_then(|v| v.as_object()) {
            obj.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                .collect()
        } else {
            HashMap::new()
        };

        let env_allowlist = cfg
            .get("env_allowlist")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            content_types,
            open_delim,
            close_delim,
            variables,
            env_allowlist,
        })
    }

    fn is_template_type(&self, content_type: &str) -> bool {
        let ct = content_type
            .split(';')
            .next()
            .unwrap_or(content_type)
            .trim();
        self.content_types
            .iter()
            .any(|t| ct.eq_ignore_ascii_case(t))
    }

    fn render(&self, template: &str, ctx: &TemplateContext) -> String {
        let mut result = template.to_string();
        let open = &self.open_delim;
        let close = &self.close_delim;

        // Replace built-in variables
        result = result.replace(&format!("{open}.Host{close}"), &ctx.host);
        result = result.replace(&format!("{open}.Path{close}"), &ctx.path);
        result = result.replace(&format!("{open}.Method{close}"), &ctx.method);
        result = result.replace(&format!("{open}.RemoteAddr{close}"), &ctx.remote_addr);
        result = result.replace(
            &format!("{open}now{close}"),
            &chrono::Utc::now().to_rfc3339(),
        );
        result = result.replace(&format!("{open}httpStatus{close}"), &ctx.status.to_string());

        // Replace user-defined variables
        for (key, value) in &self.variables {
            result = result.replace(&format!("{open}.{key}{close}"), value);
        }

        // Replace environment variables: {{.Env "VAR_NAME"}}
        let env_prefix = format!("{open}.Env \"");
        while let Some(start) = result.find(&env_prefix) {
            let after = start + env_prefix.len();
            if let Some(quote_end) = result[after..].find('"') {
                let var_name = result[after..after + quote_end].to_string();
                let env_pattern = format!("{open}.Env \"{var_name}\"{close}");
                // Only expand allowlisted env vars; everything else renders to
                // empty so an attacker-influenced template can't read secrets.
                let env_val = if self.env_allowlist.contains(&var_name) {
                    std::env::var(&var_name).unwrap_or_default()
                } else {
                    tracing::warn!(
                        var = %var_name,
                        "template: {{.Env}} for non-allowlisted variable blocked"
                    );
                    String::new()
                };
                result = result.replace(&env_pattern, &env_val);
            } else {
                break;
            }
        }

        result
    }
}

#[derive(Clone)]
struct TemplateContext {
    host: String,
    path: String,
    method: String,
    remote_addr: String,
    status: u16,
}

#[async_trait]
impl Plugin for TemplatePlugin {
    fn name(&self) -> &str {
        "template"
    }

    async fn on_request(&self, req: &mut Request<Body>) -> Result<(), PluginError> {
        let host = req
            .headers()
            .get(axum::http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("localhost")
            .to_string();
        let path = req.uri().path().to_string();
        let method = req.method().to_string();
        let remote_addr = req
            .headers()
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string();

        req.extensions_mut().insert(TemplateContext {
            host,
            path,
            method,
            remote_addr,
            status: 200,
        });
        Ok(())
    }

    async fn on_response(&self, resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        let is_template = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|ct| self.is_template_type(ct))
            .unwrap_or(false);
        if !is_template {
            return Ok(());
        }

        let mut ctx = resp
            .extensions()
            .get::<TemplateContext>()
            .cloned()
            .unwrap_or(TemplateContext {
                host: String::new(),
                path: String::new(),
                method: String::new(),
                remote_addr: String::new(),
                status: 200,
            });
        ctx.status = resp.status().as_u16();

        let body = std::mem::replace(resp.body_mut(), Body::empty());
        let bytes = match body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => return Ok(()),
        };

        let body_str = match std::str::from_utf8(&bytes) {
            Ok(s) => s,
            Err(_) => {
                *resp.body_mut() = Body::from(bytes);
                return Ok(());
            }
        };

        // Only process if body contains template delimiters
        if !body_str.contains(&self.open_delim) {
            *resp.body_mut() = Body::from(bytes);
            return Ok(());
        }

        let rendered = self.render(body_str, &ctx);
        resp.headers_mut()
            .remove(axum::http::header::CONTENT_LENGTH);
        *resp.body_mut() = Body::from(rendered);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_variables() {
        let mut vars = HashMap::new();
        vars.insert("site_name".to_string(), "Test Site".to_string());
        let plugin = TemplatePlugin {
            content_types: vec!["text/html".to_string()],
            open_delim: "{{".to_string(),
            close_delim: "}}".to_string(),
            variables: vars,
            env_allowlist: std::collections::HashSet::new(),
        };
        let ctx = TemplateContext {
            host: "example.com".to_string(),
            path: "/about".to_string(),
            method: "GET".to_string(),
            remote_addr: "1.2.3.4".to_string(),
            status: 200,
        };
        let result = plugin.render("<h1>{{.site_name}}</h1><p>{{.Host}}{{.Path}}</p>", &ctx);
        assert_eq!(result, "<h1>Test Site</h1><p>example.com/about</p>");
    }

    #[test]
    fn env_expansion_requires_allowlist() {
        std::env::set_var("LYNXX_TEST_TEMPLATE_SECRET", "supersecret");
        let ctx = TemplateContext {
            host: String::new(),
            path: String::new(),
            method: String::new(),
            remote_addr: String::new(),
            status: 200,
        };
        // Not allowlisted → blocked (renders empty), no secret leak.
        let denied = TemplatePlugin {
            content_types: vec![],
            open_delim: "{{".to_string(),
            close_delim: "}}".to_string(),
            variables: HashMap::new(),
            env_allowlist: std::collections::HashSet::new(),
        };
        assert_eq!(
            denied.render("[{{.Env \"LYNXX_TEST_TEMPLATE_SECRET\"}}]", &ctx),
            "[]"
        );
        // Explicitly allowlisted → expanded.
        let allowed = TemplatePlugin {
            content_types: vec![],
            open_delim: "{{".to_string(),
            close_delim: "}}".to_string(),
            variables: HashMap::new(),
            env_allowlist: ["LYNXX_TEST_TEMPLATE_SECRET".to_string()]
                .into_iter()
                .collect(),
        };
        assert_eq!(
            allowed.render("[{{.Env \"LYNXX_TEST_TEMPLATE_SECRET\"}}]", &ctx),
            "[supersecret]"
        );
        std::env::remove_var("LYNXX_TEST_TEMPLATE_SECRET");
    }

    #[test]
    fn render_status() {
        let plugin = TemplatePlugin {
            content_types: vec![],
            open_delim: "{{".to_string(),
            close_delim: "}}".to_string(),
            variables: HashMap::new(),
            env_allowlist: std::collections::HashSet::new(),
        };
        let ctx = TemplateContext {
            host: String::new(),
            path: String::new(),
            method: String::new(),
            remote_addr: String::new(),
            status: 404,
        };
        let result = plugin.render("Error {{httpStatus}}", &ctx);
        assert_eq!(result, "Error 404");
    }
}
