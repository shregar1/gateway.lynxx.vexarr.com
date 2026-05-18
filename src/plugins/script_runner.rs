use crate::error::{GatewayError, PluginError, SyncBody};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::header::{HeaderName, HeaderValue};
use axum::http::{Request, Response};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};

/// Maximum body bytes we will buffer for script I/O (default 2 MB).
const DEFAULT_MAX_BODY: usize = 2 * 1024 * 1024;
/// Default script timeout (5 seconds).
const DEFAULT_TIMEOUT_MS: u64 = 5000;

/// Request context stashed in extensions during `on_request` so that
/// `on_response` can access the original request method, path, and any
/// `x-lynxx-*` headers set by pre-request scripts (e.g. reference URN
/// propagation). The proxy handler transfers extensions from the request
/// to the response automatically.
#[derive(Clone, Debug)]
pub struct ScriptRequestContext {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: HashMap<String, String>,
}

// ─── Config ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ScriptDef {
    command: String,
    args: Vec<String>,
    timeout: Duration,
    working_dir: Option<String>,
}

pub struct ScriptRunnerPlugin {
    on_request: Option<ScriptDef>,
    on_response: Option<ScriptDef>,
    env: HashMap<String, String>,
    max_body_bytes: usize,
}

impl ScriptRunnerPlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let on_request = parse_script_def(cfg.get("on_request"))?;
        let on_response = parse_script_def(cfg.get("on_response"))?;

        if on_request.is_none() && on_response.is_none() {
            return Err(GatewayError::BadRequest(
                "script-runner: at least one of `on_request` or `on_response` must be configured"
                    .into(),
            ));
        }

        let env = cfg
            .get("env")
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        let max_body_bytes = cfg
            .get("max_body_bytes")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(DEFAULT_MAX_BODY);

        Ok(Self {
            on_request,
            on_response,
            env,
            max_body_bytes,
        })
    }
}

fn parse_script_def(val: Option<&serde_json::Value>) -> Result<Option<ScriptDef>, GatewayError> {
    let Some(obj) = val.and_then(|v| v.as_object()) else {
        return Ok(None);
    };

    let command = obj
        .get("command")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            GatewayError::BadRequest("script-runner: `command` is required in script def".into())
        })?
        .to_string();

    let args = obj
        .get("args")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let timeout_ms = obj
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_TIMEOUT_MS);

    let working_dir = obj
        .get("working_dir")
        .and_then(|v| v.as_str())
        .map(String::from);

    Ok(Some(ScriptDef {
        command,
        args,
        timeout: Duration::from_millis(timeout_ms),
        working_dir,
    }))
}

// ─── Script I/O Types ────────────────────────────────────────────────────────

/// JSON piped to the script's stdin.
#[derive(Serialize)]
struct ScriptInput {
    phase: &'static str,
    // request fields (always present)
    method: String,
    path: String,
    query: String,
    headers: HashMap<String, String>,
    body_base64: String,
    body_size: usize,
    // response fields (only in "response" phase)
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_headers: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_size: Option<usize>,
}

/// JSON read from the script's stdout.
#[derive(Deserialize, Default)]
struct ScriptOutput {
    /// "continue" (default) | "modify" | "reject"
    #[serde(default = "default_action")]
    action: String,

    // ── For "reject" ──
    /// HTTP status code for rejection (default 403).
    #[serde(default)]
    status: Option<u16>,
    /// Body for rejection response.
    #[serde(default)]
    reject_body: Option<String>,
    /// Content-Type for rejection response.
    #[serde(default)]
    reject_content_type: Option<String>,

    // ── For "modify" ──
    /// Headers to add/overwrite.
    #[serde(default)]
    set_headers: Option<HashMap<String, String>>,
    /// Header names to remove.
    #[serde(default)]
    remove_headers: Option<Vec<String>>,
    /// Replace the body with this base64-encoded value.
    #[serde(default)]
    body_base64: Option<String>,
    /// Or replace the body with this raw string (UTF-8).
    #[serde(default)]
    body: Option<String>,
    /// Override Content-Type when replacing body.
    #[serde(default)]
    content_type: Option<String>,
    /// Override the response status code (response phase only).
    #[serde(default)]
    set_status: Option<u16>,

    // ── Metadata passthrough ──
    /// Arbitrary key-value pairs injected as x-script-* request headers.
    #[serde(default)]
    metadata: Option<HashMap<String, String>>,
}

fn default_action() -> String {
    "continue".into()
}

// ─── Script Execution ────────────────────────────────────────────────────────

async fn run_script(
    def: &ScriptDef,
    env: &HashMap<String, String>,
    input: &ScriptInput,
) -> Result<ScriptOutput, PluginError> {
    let input_json = serde_json::to_vec(input)
        .map_err(|e| PluginError::Internal(format!("script-runner: serialize input: {e}")))?;

    let mut cmd = tokio::process::Command::new(&def.command);
    cmd.args(&def.args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .envs(env);

    if let Some(ref dir) = def.working_dir {
        cmd.current_dir(dir);
    }

    let mut child = cmd.spawn().map_err(|e| {
        PluginError::Internal(format!("script-runner: spawn `{}`: {e}", def.command))
    })?;

    // Write input to stdin.
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&input_json).await.ok();
        drop(stdin); // close stdin so the script sees EOF
    }

    // Wait with timeout. We use wait() + manual stdout/stderr reads so we
    // retain ownership of `child` for the kill path.
    let wait_result = tokio::time::timeout(def.timeout, child.wait()).await;

    let exit_status = match wait_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(PluginError::Internal(format!("script-runner: wait: {e}")));
        }
        Err(_) => {
            child.kill().await.ok();
            return Err(PluginError::Internal(format!(
                "script-runner: `{}` timed out after {:?}",
                def.command, def.timeout
            )));
        }
    };

    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    if let Some(mut out) = child.stdout.take() {
        tokio::io::AsyncReadExt::read_to_end(&mut out, &mut stdout_bytes)
            .await
            .ok();
    }
    if let Some(mut err) = child.stderr.take() {
        tokio::io::AsyncReadExt::read_to_end(&mut err, &mut stderr_bytes)
            .await
            .ok();
    }

    let output = std::process::Output {
        status: exit_status,
        stdout: stdout_bytes,
        stderr: stderr_bytes,
    };

    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        debug!("script-runner stderr: {}", stderr.trim());
    }

    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        warn!(
            "script-runner: `{}` exited with code {code}: {stderr}",
            def.command,
            stderr = stderr.trim()
        );
        return Err(PluginError::Internal(format!(
            "script-runner: `{}` exited with code {code}",
            def.command
        )));
    }

    // Empty stdout → "continue" (pass-through).
    if output.stdout.is_empty() {
        return Ok(ScriptOutput::default());
    }

    serde_json::from_slice(&output.stdout).map_err(|e| {
        PluginError::Internal(format!(
            "script-runner: failed to parse script stdout as JSON: {e}"
        ))
    })
}

// ─── Header helpers ──────────────────────────────────────────────────────────

fn headers_to_map(headers: &axum::http::HeaderMap) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (k, v) in headers.iter() {
        if let Ok(s) = v.to_str() {
            map.insert(k.as_str().to_string(), s.to_string());
        }
    }
    map
}

fn apply_header_changes(
    headers: &mut axum::http::HeaderMap,
    set: &Option<HashMap<String, String>>,
    remove: &Option<Vec<String>>,
) {
    if let Some(removes) = remove {
        for name in removes {
            if let Ok(hn) = HeaderName::from_str(name) {
                headers.remove(&hn);
            }
        }
    }
    if let Some(sets) = set {
        for (k, v) in sets {
            if let (Ok(hn), Ok(hv)) = (HeaderName::from_str(k), HeaderValue::from_str(v)) {
                headers.insert(hn, hv);
            }
        }
    }
}

fn resolve_body(out: &ScriptOutput) -> Option<Vec<u8>> {
    if let Some(ref b64) = out.body_base64 {
        if let Ok(decoded) = B64.decode(b64) {
            return Some(decoded);
        }
    }
    if let Some(ref raw) = out.body {
        return Some(raw.as_bytes().to_vec());
    }
    None
}

// ─── Plugin trait ────────────────────────────────────────────────────────────

#[async_trait]
impl Plugin for ScriptRunnerPlugin {
    fn name(&self) -> &str {
        "script-runner"
    }

    async fn on_request(&self, req: &mut Request<Body>) -> Result<(), PluginError> {
        let Some(ref def) = self.on_request else {
            return Ok(());
        };

        // Drain body for the script.
        let body = std::mem::replace(req.body_mut(), Body::empty());
        let body_bytes = body
            .collect()
            .await
            .map_err(|e| PluginError::Internal(format!("script-runner: body collect: {e}")))?
            .to_bytes();

        let truncated = if body_bytes.len() > self.max_body_bytes {
            &body_bytes[..self.max_body_bytes]
        } else {
            &body_bytes[..]
        };

        let input = ScriptInput {
            phase: "request",
            method: req.method().to_string(),
            path: req.uri().path().to_string(),
            query: req.uri().query().unwrap_or("").to_string(),
            headers: headers_to_map(req.headers()),
            body_base64: B64.encode(truncated),
            body_size: body_bytes.len(),
            status: None,
            response_headers: None,
            response_body_base64: None,
            response_body_size: None,
        };

        let out = run_script(def, &self.env, &input).await?;

        match out.action.as_str() {
            "reject" => {
                let status = out.status.unwrap_or(403);
                let body_bytes = out.reject_body.unwrap_or_default().into_bytes();
                let ct = out
                    .reject_content_type
                    .unwrap_or_else(|| "application/json".into());
                return Err(PluginError::ShortCircuit {
                    status,
                    headers: vec![("content-type".into(), ct)],
                    body: SyncBody::from(body_bytes),
                });
            }
            "modify" => {
                apply_header_changes(req.headers_mut(), &out.set_headers, &out.remove_headers);

                if let Some(new_body) = resolve_body(&out) {
                    if let Some(ref ct) = out.content_type {
                        if let Ok(hv) = HeaderValue::from_str(ct) {
                            req.headers_mut()
                                .insert(axum::http::header::CONTENT_TYPE, hv);
                        }
                    }
                    *req.body_mut() = Body::from(new_body);
                } else {
                    // Restore original body.
                    *req.body_mut() = Body::from(body_bytes.to_vec());
                }

                // Inject metadata as x-script-* headers.
                if let Some(ref meta) = out.metadata {
                    for (k, v) in meta {
                        let name = format!("x-script-{k}");
                        if let (Ok(hn), Ok(hv)) =
                            (HeaderName::from_str(&name), HeaderValue::from_str(v))
                        {
                            req.headers_mut().insert(hn, hv);
                        }
                    }
                }
            }
            _ => {
                // "continue" — restore body unchanged.
                *req.body_mut() = Body::from(body_bytes.to_vec());
            }
        }

        // Stash request context so on_response can access method, path,
        // query, and any x-lynxx-* headers set by this script. The proxy
        // handler transfers extensions from req → resp automatically.
        let ctx = ScriptRequestContext {
            method: req.method().to_string(),
            path: req.uri().path().to_string(),
            query: req.uri().query().unwrap_or("").to_string(),
            headers: headers_to_map(req.headers()),
        };
        req.extensions_mut().insert(ctx);

        Ok(())
    }

    async fn on_response(&self, resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        let Some(ref def) = self.on_response else {
            return Ok(());
        };

        // Drain response body for script processing.
        let body = std::mem::replace(resp.body_mut(), Body::empty());
        let body_bytes = body
            .collect()
            .await
            .map_err(|e| PluginError::Internal(format!("script-runner: resp body collect: {e}")))?
            .to_bytes();

        let truncated = if body_bytes.len() > self.max_body_bytes {
            &body_bytes[..self.max_body_bytes]
        } else {
            &body_bytes[..]
        };

        // Recover request context stashed by on_request via extensions.
        // Falls back to x-original-method/uri response headers (legacy) or
        // empty strings when neither is available.
        let ctx = resp.extensions().get::<ScriptRequestContext>().cloned();
        let (req_method, req_path, req_query, req_headers) = match ctx {
            Some(c) => (c.method, c.path, c.query, c.headers),
            None => {
                let m = resp
                    .headers()
                    .get("x-original-method")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let p = resp
                    .headers()
                    .get("x-original-uri")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                (m, p, String::new(), HashMap::new())
            }
        };

        let input = ScriptInput {
            phase: "response",
            method: req_method,
            path: req_path,
            query: req_query,
            headers: req_headers,
            body_base64: String::new(),
            body_size: 0,
            status: Some(resp.status().as_u16()),
            response_headers: Some(headers_to_map(resp.headers())),
            response_body_base64: Some(B64.encode(truncated)),
            response_body_size: Some(body_bytes.len()),
        };

        let out = run_script(def, &self.env, &input).await?;

        match out.action.as_str() {
            "reject" => {
                let status = out.status.unwrap_or(resp.status().as_u16());
                let body_bytes = out.reject_body.unwrap_or_default().into_bytes();
                let ct = out
                    .reject_content_type
                    .unwrap_or_else(|| "application/json".into());
                return Err(PluginError::ShortCircuit {
                    status,
                    headers: vec![("content-type".into(), ct)],
                    body: SyncBody::from(body_bytes),
                });
            }
            "modify" => {
                // Build a new response via ShortCircuit to avoid hyper's
                // content-length validation on the original response body.
                let new_body = resolve_body(&out).unwrap_or_else(|| body_bytes.to_vec());
                let status = out.set_status.unwrap_or(resp.status().as_u16());
                let ct = out.content_type.unwrap_or_else(|| {
                    resp.headers()
                        .get(axum::http::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("application/octet-stream")
                        .to_string()
                });

                // Collect existing headers, apply changes, then emit.
                let mut headers: Vec<(String, String)> = resp
                    .headers()
                    .iter()
                    .filter(|(k, _)| {
                        *k != axum::http::header::CONTENT_LENGTH
                            && *k != axum::http::header::TRANSFER_ENCODING
                            && *k != axum::http::header::CONTENT_TYPE
                    })
                    .filter_map(|(k, v)| {
                        v.to_str()
                            .ok()
                            .map(|s| (k.as_str().to_string(), s.to_string()))
                    })
                    .collect();

                headers.push(("content-type".into(), ct));

                // Apply set/remove from script output.
                if let Some(ref removes) = out.remove_headers {
                    headers.retain(|(k, _)| !removes.iter().any(|r| r.eq_ignore_ascii_case(k)));
                }
                if let Some(ref sets) = out.set_headers {
                    for (k, v) in sets {
                        headers.retain(|(hk, _)| !hk.eq_ignore_ascii_case(k));
                        headers.push((k.clone(), v.clone()));
                    }
                }

                // Inject metadata as x-script-* headers.
                if let Some(ref meta) = out.metadata {
                    for (k, v) in meta {
                        headers.push((format!("x-script-{k}"), v.clone()));
                    }
                }

                return Err(PluginError::ShortCircuit {
                    status,
                    headers,
                    body: SyncBody::from(new_body),
                });
            }
            _ => {
                // Restore original body via ShortCircuit to avoid hyper
                // content-length mismatch after body drain.
                let status = resp.status().as_u16();
                let headers: Vec<(String, String)> = resp
                    .headers()
                    .iter()
                    .filter(|(k, _)| {
                        *k != axum::http::header::CONTENT_LENGTH
                            && *k != axum::http::header::TRANSFER_ENCODING
                    })
                    .filter_map(|(k, v)| {
                        v.to_str()
                            .ok()
                            .map(|s| (k.as_str().to_string(), s.to_string()))
                    })
                    .collect();

                Err(PluginError::ShortCircuit {
                    status,
                    headers,
                    body: SyncBody::from(body_bytes.to_vec()),
                })
            }
        }
    }
}
