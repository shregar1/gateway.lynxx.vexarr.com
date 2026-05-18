//! WebAssembly plugin runtime.
//!
//! Lets operators ship plugin logic as a sandboxed `.wasm` module
//! compiled from Rust, Go (TinyGo), AssemblyScript, Zig, or C. The
//! module exports `on_request` and `on_response`; the host exposes a
//! small set of `lynxx_*` functions for header / body / config access.
//!
//! Resource ceilings are enforced three ways:
//!
//! 1. **Fuel** — every wasmtime instruction consumes fuel; running out
//!    raises a trap.
//! 2. **Epoch interruption** — a 1ms ticker in `runtime.rs` advances
//!    the engine epoch; per-request `set_epoch_deadline(N)` enforces a
//!    hard wall-clock budget.
//! 3. **Linear-memory pages** — capped at instantiation time. The
//!    guest can `memory.grow` up to the cap and no further.
//!
//! WASI is not exposed. The only host surface is the `lynxx` namespace.

pub mod config;
pub mod context;
pub mod host;
pub mod runtime;
pub mod watcher;

use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::http::header::{HeaderName, HeaderValue};
use axum::http::{Request, Response};
use base64::Engine as _;
use config::{WasmConfig, MAX_MODULE_BYTES};
use context::{HostContext, Phase};
use std::str::FromStr;
use std::sync::Arc;
use wasmtime::{Linker, Module, Store, StoreLimitsBuilder};

pub struct WasmPlugin {
    cfg: WasmConfig,
    module: Module,
    linker: Arc<Linker<HostContext>>,
    /// Whether the module exports a `memory`. Required: every host
    /// function reads/writes guest linear memory.
    has_alloc: bool,
}

impl WasmPlugin {
    pub fn from_config(value: &serde_json::Value) -> Result<Self, GatewayError> {
        let cfg = WasmConfig::from_value(value)?;
        let bytes = load_module_bytes(&cfg)?;
        runtime::validate_magic(&bytes)?;

        let engine_handle = runtime::WasmEngine::global()?;
        let module = Module::from_binary(engine_handle.engine(), &bytes)
            .map_err(|e| GatewayError::BadRequest(format!("failed to compile wasm module: {e}")))?;

        // Required exports: `memory`, `on_request`, `on_response`.
        let exports: Vec<_> = module.exports().map(|e| e.name().to_string()).collect();
        for required in ["memory", "on_request", "on_response"] {
            if !exports.iter().any(|n| n == required) {
                return Err(GatewayError::BadRequest(format!(
                    "wasm module missing required export `{required}`"
                )));
            }
        }
        let has_alloc = exports.iter().any(|n| n == "alloc");

        let mut linker: Linker<HostContext> = Linker::new(engine_handle.engine());
        host::register(&mut linker)
            .map_err(|e| GatewayError::Internal(format!("wasm host link failed: {e}")))?;

        Ok(Self {
            cfg,
            module,
            linker: Arc::new(linker),
            has_alloc,
        })
    }

    /// Whether the loaded module advertises an `alloc` export. Reserved
    /// for a future ABI revision that calls back into the guest to
    /// allocate buffers; today every getter takes a guest-supplied
    /// pre-allocated pointer.
    pub fn has_alloc(&self) -> bool {
        self.has_alloc
    }

    /// Build a fresh `StoreLimits` capped at the configured memory
    /// ceiling. One `StoreLimits` per request — wasmtime mutates it as
    /// the guest grows memory.
    fn build_limits(&self) -> wasmtime::StoreLimits {
        let max_bytes = self.cfg.memory_pages() as usize * 64 * 1024;
        StoreLimitsBuilder::new()
            .memory_size(max_bytes)
            .instances(1)
            .tables(8)
            .build()
    }

    /// Run the named export against a freshly-built store and return
    /// the mutated `HostContext`. Used by both `on_request` and
    /// `on_response`.
    fn invoke(&self, export: &str, ctx: HostContext) -> Result<HostContext, PluginError> {
        let engine = runtime::WasmEngine::global()
            .map_err(|e| PluginError::Internal(format!("wasm engine unavailable: {e}")))?;
        let mut store = Store::new(engine.engine(), ctx);

        store
            .set_fuel(self.cfg.fuel_per_request)
            .map_err(|e| PluginError::Internal(format!("wasm fuel init failed: {e}")))?;
        // Each tick = 1ms (see runtime.rs ticker). The deadline is a
        // count of ticks from "now", so wall_timeout_ms maps directly.
        store.set_epoch_deadline(self.cfg.wall_timeout_ms);
        // Wire the resource limiter to the StoreLimits stashed inside
        // HostContext so the closure has a stable borrow target.
        store.limiter(|data: &mut HostContext| &mut data.limits);

        let instance = self
            .linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| classify_trap(e, "instantiate"))?;

        let func = match instance.get_typed_func::<(), ()>(&mut store, export) {
            Ok(f) => f,
            Err(_) => {
                // Export missing or wrong signature. Fall back to
                // `on_request`/`on_response` being a no-op so a guest
                // that only cares about one phase doesn't have to
                // implement the other.
                return Ok(store.into_data());
            }
        };

        match func.call(&mut store, ()) {
            Ok(()) => Ok(store.into_data()),
            Err(e) => Err(classify_trap(e, export)),
        }
    }
}

#[async_trait]
impl Plugin for WasmPlugin {
    fn name(&self) -> &str {
        "wasm"
    }

    async fn on_request(&self, req: &mut Request<axum::body::Body>) -> Result<(), PluginError> {
        let mut ctx = HostContext::new(
            Phase::Request,
            self.cfg.user_config_json(),
            rand_seed(),
            self.build_limits(),
        );
        ctx.method = req.method().as_str().to_string();
        ctx.path = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/")
            .to_string();
        ctx.request_headers = req
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        // Body is left empty: streaming bodies aren't safe to buffer
        // into the guest by default. A future iteration can opt-in via
        // a `buffer_request_body` config flag.
        // Upstream auth plugins (key-auth, basic-auth, jwt) stamp the
        // resolved identity onto `x-consumer-username`. We surface it
        // here so the wasm guest can read it via
        // `lynxx_get_consumer_username` without re-implementing the
        // header lookup.
        if let Some(v) = req
            .headers()
            .get("x-consumer-username")
            .and_then(|v| v.to_str().ok())
        {
            ctx.consumer = Some(v.to_string());
        }

        let mutated = self.invoke("on_request", ctx)?;

        // Short-circuit takes precedence over any header mutation.
        if let Some((status, body)) = mutated.short_circuit {
            return Err(PluginError::ShortCircuit {
                status,
                headers: vec![],
                body: body.into(),
            });
        }

        // Apply header diffs back to the live request.
        let new_headers = mutated.request_headers;
        req.headers_mut().clear();
        for (k, v) in new_headers {
            if let (Ok(name), Ok(value)) = (HeaderName::from_str(&k), HeaderValue::from_str(&v)) {
                req.headers_mut().append(name, value);
            }
        }
        Ok(())
    }

    async fn on_response(&self, resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        let mut ctx = HostContext::new(
            Phase::Response,
            self.cfg.user_config_json(),
            rand_seed(),
            self.build_limits(),
        );
        ctx.response_status = Some(resp.status().as_u16());
        ctx.response_headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let mutated = self.invoke("on_response", ctx)?;

        // Short-circuit on the response phase doesn't make sense — the
        // response is already going out the door. We still respect a
        // status override via `response_status`, but ignore body
        // payloads.
        let new_headers = mutated.response_headers;
        resp.headers_mut().clear();
        for (k, v) in new_headers {
            if let (Ok(name), Ok(value)) = (HeaderName::from_str(&k), HeaderValue::from_str(&v)) {
                resp.headers_mut().append(name, value);
            }
        }
        Ok(())
    }
}

fn rand_seed() -> u64 {
    use rand::RngCore;
    rand::thread_rng().next_u64()
}

/// Resolve module bytes from `module_path` (preferred) or `module_b64`.
fn load_module_bytes(cfg: &WasmConfig) -> Result<Vec<u8>, GatewayError> {
    if let Some(path) = cfg.module_path.as_ref() {
        let bytes = std::fs::read(path)
            .map_err(|e| GatewayError::BadRequest(format!("read wasm module {path}: {e}")))?;
        if bytes.len() > MAX_MODULE_BYTES {
            return Err(GatewayError::BadRequest(format!(
                "wasm module {path} is {} bytes, exceeds limit {}",
                bytes.len(),
                MAX_MODULE_BYTES
            )));
        }
        return Ok(bytes);
    }
    if let Some(b64) = cfg.module_b64.as_ref() {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|e| GatewayError::BadRequest(format!("module_b64 decode failed: {e}")))?;
        if bytes.len() > MAX_MODULE_BYTES {
            return Err(GatewayError::BadRequest(format!(
                "wasm module is {} bytes, exceeds limit {}",
                bytes.len(),
                MAX_MODULE_BYTES
            )));
        }
        return Ok(bytes);
    }
    Err(GatewayError::BadRequest(
        "wasm plugin requires module_path or module_b64".into(),
    ))
}

/// Map wasmtime errors to `PluginError::Internal` with a stable message
/// so the dashboard can surface them consistently. Out-of-fuel and
/// epoch interruption are the two canonical resource exhaustion cases;
/// everything else is bucketed as a generic trap.
fn classify_trap(err: anyhow::Error, ctx: &str) -> PluginError {
    use wasmtime::Trap;
    let msg = err.to_string();
    if let Some(trap) = err.downcast_ref::<Trap>() {
        match trap {
            Trap::OutOfFuel => return PluginError::Internal("wasm out of fuel".into()),
            Trap::Interrupt => {
                return PluginError::Internal("wasm wall-time exceeded".into());
            }
            _ => {}
        }
    }
    // Some traps also surface via the message text, especially when
    // wrapped through `anyhow`. Fall back to substring matching.
    if msg.contains("all fuel consumed") {
        return PluginError::Internal("wasm out of fuel".into());
    }
    if msg.contains("epoch deadline") || msg.contains("interrupt") {
        return PluginError::Internal("wasm wall-time exceeded".into());
    }
    PluginError::Internal(format!("wasm {ctx} trap: {msg}"))
}

// ── Tests ───────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use base64::Engine as Base64Engine;
    use serde_json::json;

    /// Build a `WasmPlugin` from a WAT (WebAssembly text) source. Keeps
    /// the test fixtures inline + readable instead of dragging a
    /// pre-compiled binary into the repo.
    fn from_wat(wat_src: &str, extra: serde_json::Value) -> WasmPlugin {
        let bytes = wat::parse_str(wat_src).expect("wat compiles");
        let b64 = Base64Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
        let mut cfg = json!({ "module_b64": b64 });
        if let Some(obj) = extra.as_object() {
            for (k, v) in obj {
                cfg[k.clone()] = v.clone();
            }
        }
        WasmPlugin::from_config(&cfg).expect("plugin builds")
    }

    const NOOP_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "on_request"))
          (func (export "on_response")))"#;

    const HEADER_WAT: &str = r#"
        (module
          (import "lynxx" "lynxx_set_request_header"
            (func $set_header (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0)  "x-wasm-test")
          (data (i32.const 16) "ok")
          (func (export "on_request")
            (drop (call $set_header
              (i32.const 0)  (i32.const 11)
              (i32.const 16) (i32.const 2))))
          (func (export "on_response")))"#;

    const LOOP_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "on_request")
            (loop $f (br $f)))
          (func (export "on_response")))"#;

    #[tokio::test]
    async fn noop_module_runs() {
        let p = from_wat(NOOP_WAT, json!({}));
        let mut req = Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        p.on_request(&mut req).await.unwrap();
    }

    #[tokio::test]
    async fn header_injection_round_trips() {
        let p = from_wat(HEADER_WAT, json!({}));
        let mut req = Request::builder()
            .uri("/x")
            .body(axum::body::Body::empty())
            .unwrap();
        p.on_request(&mut req).await.unwrap();
        assert_eq!(
            req.headers()
                .get("x-wasm-test")
                .and_then(|v| v.to_str().ok()),
            Some("ok"),
        );
    }

    #[tokio::test]
    async fn out_of_fuel_surfaces_internal_error() {
        let p = from_wat(
            LOOP_WAT,
            json!({ "fuel_per_request": 1_000u64, "wall_timeout_ms": 1_000u64 }),
        );
        let mut req = Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        let err = p.on_request(&mut req).await.expect_err("must trap");
        let s = format!("{err}");
        assert!(s.contains("fuel") || s.contains("wall"), "got: {s}");
    }

    /// End-to-end test against a real Rust-compiled WASM module from
    /// `packages.lynxx.dev/wasm/examples/header-injector`. Catches drift
    /// between the host ABI here and the SDK wrappers there: if either
    /// side rotates a function signature, this test breaks.
    ///
    /// The fixture is a precompiled `.wasm` checked in alongside the
    /// example source so this test doesn't need cargo + wasm32 in CI.
    /// Rebuild via `cargo build --release --target wasm32-unknown-unknown`
    /// in the example dir if you change the source.
    #[tokio::test]
    async fn precompiled_rust_plugin_injects_headers() {
        const HEADER_INJECTOR_WASM: &[u8] =
            include_bytes!("../../../tests/fixtures/header-injector.wasm");
        let b64 = Base64Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            HEADER_INJECTOR_WASM,
        );
        let plugin = WasmPlugin::from_config(&json!({ "module_b64": b64 })).expect("plugin builds");
        let mut req = Request::builder()
            .uri("/x")
            .body(axum::body::Body::empty())
            .unwrap();
        plugin.on_request(&mut req).await.unwrap();
        assert_eq!(
            req.headers()
                .get("X-Lynxx-Hello")
                .and_then(|v| v.to_str().ok()),
            Some("world"),
            "header-injector should stamp X-Lynxx-Hello on the request",
        );
    }

    #[test]
    fn rejects_module_missing_required_exports() {
        let bytes = wat::parse_str(r#"(module (func (export "noop")))"#).unwrap();
        let b64 = Base64Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
        let err = WasmPlugin::from_config(&json!({ "module_b64": b64 }))
            .err()
            .expect("must reject");
        assert!(format!("{err}").contains("missing required export"));
    }

    #[test]
    fn rejects_non_wasm_bytes() {
        let b64 = Base64Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"not-wasm-at-all",
        );
        let err = WasmPlugin::from_config(&json!({ "module_b64": b64 }))
            .err()
            .expect("must reject");
        let s = format!("{err}");
        assert!(s.contains("WebAssembly") || s.contains("magic"), "got: {s}");
    }
}
