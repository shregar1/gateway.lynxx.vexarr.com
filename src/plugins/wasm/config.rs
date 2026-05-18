//! Configuration for the WASM plugin runtime.
//!
//! Plugins persist their config as JSON in the DB; this module owns the
//! deserialization + validation step that turns that blob into typed,
//! resource-bounded knobs the runtime can rely on.

use crate::error::GatewayError;
use serde::Deserialize;

/// Hard cap on module size when loading from disk. WebAssembly modules
/// larger than 5MB are almost always shipping debug info or a bundled
/// runtime — both red flags for an in-process plugin sandbox.
pub const MAX_MODULE_BYTES: usize = 5 * 1024 * 1024;

/// Default fuel budget per request. ~10M wasmtime fuel units roughly
/// corresponds to ~1ms of CPU on a modern x86 core for branchy bytecode.
pub const DEFAULT_FUEL_PER_REQUEST: u64 = 10_000_000;

/// Default linear-memory cap. 16MB = 256 pages of 64KB.
pub const DEFAULT_MEMORY_MAX_KB: u32 = 16 * 1024;

/// Default wall-clock timeout in milliseconds. The epoch ticker fires once
/// every 1ms, so this also doubles as the number of epoch ticks granted
/// to a request before the host interrupts.
pub const DEFAULT_WALL_TIMEOUT_MS: u64 = 50;

#[derive(Debug, Clone, Deserialize)]
pub struct WasmConfig {
    /// Filesystem path to a `.wasm` module. Read once at plugin build time
    /// and compiled. Mutually-exclusive with `module_b64` — if both are
    /// supplied, `module_path` wins.
    #[serde(default)]
    pub module_path: Option<String>,

    /// Base64-encoded module bytes. Useful for the dashboard upload flow
    /// where the operator drops a `.wasm` file into the form.
    #[serde(default)]
    pub module_b64: Option<String>,

    /// Per-request fuel budget. Each WebAssembly instruction consumes
    /// fuel; running out raises a trap that the host maps to an internal
    /// plugin error.
    #[serde(default = "default_fuel")]
    pub fuel_per_request: u64,

    /// Linear-memory cap in kilobytes. Rounded up to the nearest 64KB
    /// page; minimum 1 page (64KB).
    #[serde(default = "default_memory_kb")]
    pub memory_max_kb: u32,

    /// Wall-clock budget in milliseconds. Enforced via wasmtime's epoch
    /// interruption — a background task increments the engine epoch every
    /// 1ms, so this value also acts as the deadline tick count.
    #[serde(default = "default_wall_ms")]
    pub wall_timeout_ms: u64,

    /// Free-form JSON forwarded verbatim to the guest via `lynxx_get_config`.
    /// Lets a single compiled module be reused across plugin instances with
    /// per-instance tuning (e.g. the same JWT validator with different
    /// audiences).
    #[serde(default)]
    pub user_config: Option<serde_json::Value>,
}

fn default_fuel() -> u64 {
    DEFAULT_FUEL_PER_REQUEST
}
fn default_memory_kb() -> u32 {
    DEFAULT_MEMORY_MAX_KB
}
fn default_wall_ms() -> u64 {
    DEFAULT_WALL_TIMEOUT_MS
}

impl WasmConfig {
    pub fn from_value(value: &serde_json::Value) -> Result<Self, GatewayError> {
        let cfg: WasmConfig = serde_json::from_value(value.clone())
            .map_err(|e| GatewayError::BadRequest(format!("invalid wasm config: {e}")))?;

        if cfg.module_path.is_none() && cfg.module_b64.is_none() {
            return Err(GatewayError::BadRequest(
                "wasm plugin requires either `module_path` or `module_b64`".into(),
            ));
        }
        if cfg.fuel_per_request == 0 {
            return Err(GatewayError::BadRequest(
                "wasm plugin `fuel_per_request` must be > 0".into(),
            ));
        }
        if cfg.memory_max_kb == 0 {
            return Err(GatewayError::BadRequest(
                "wasm plugin `memory_max_kb` must be > 0".into(),
            ));
        }
        if cfg.wall_timeout_ms == 0 {
            return Err(GatewayError::BadRequest(
                "wasm plugin `wall_timeout_ms` must be > 0".into(),
            ));
        }
        Ok(cfg)
    }

    /// Serialize the user-supplied config blob for delivery to the guest.
    /// Always returns a valid JSON document; defaults to `{}` when no
    /// config was provided.
    pub fn user_config_json(&self) -> String {
        match &self.user_config {
            Some(v) => v.to_string(),
            None => "{}".to_string(),
        }
    }

    /// Convert the kilobyte cap into wasmtime memory pages (64KB each),
    /// rounding up so the operator's intent is honored even on
    /// non-page-aligned values.
    pub fn memory_pages(&self) -> u32 {
        let pages = self.memory_max_kb.div_ceil(64);
        pages.max(1)
    }
}
