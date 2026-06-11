//! Host ABI exposed to a WASM guest.
//!
//! All host functions follow the same convention:
//!
//! * Getters of the form `lynxx_get_*(out_ptr, out_max_len)` write up to
//!   `out_max_len` bytes of UTF-8 (or arbitrary bytes for the body) into
//!   guest linear memory and return the number of bytes written.
//!     * `-1` if the value does not exist.
//!     * `-2` if `out_max_len` is too small.
//! * Setters return `0` on success, negative on error.
//!
//! The guest is expected to export an `alloc(size: i32) -> i32` function
//! that returns a pointer into linear memory; the host calls it for any
//! function that needs a guest-owned buffer (today, none — getters all
//! take a pre-allocated buffer pointer). `alloc` is therefore optional.

use super::context::{HostContext, Phase};
use std::time::{SystemTime, UNIX_EPOCH};
use wasmtime::{Caller, Extern, Linker, Memory};

/// Status codes returned by getters. Negative numbers are reserved for
/// errors so the guest can distinguish "no value" from "buffer too small".
const ERR_NOT_FOUND: i32 = -1;
const ERR_BUFFER_TOO_SMALL: i32 = -2;
const ERR_OUT_OF_BOUNDS: i32 = -3;
const ERR_INVALID_UTF8: i32 = -4;
const ERR_WRONG_PHASE: i32 = -5;
const ERR_TOO_LARGE: i32 = -6;

/// Upper bound on a single `lynxx_random_bytes` request. The guest controls
/// `len`, and the host allocates a buffer of that size BEFORE touching wasm
/// memory, so an unbounded value (up to i32::MAX ≈ 2 GiB) is a trivial host
/// OOM. 64 KiB is far more than any legitimate jitter/id use needs.
const MAX_RANDOM_BYTES: usize = 64 * 1024;

/// Wire up every `lynxx_*` host function on the supplied linker. Called
/// once per `WasmPlugin` instance; the linker is then reused to
/// instantiate the module on every request.
pub fn register(linker: &mut Linker<HostContext>) -> wasmtime::Result<()> {
    // ── Logging ─────────────────────────────────────────────────────────
    linker.func_wrap(
        "lynxx",
        "lynxx_log",
        |mut caller: Caller<'_, HostContext>, level: i32, ptr: i32, len: i32| {
            let memory = match get_memory(&mut caller) {
                Some(m) => m,
                None => return,
            };
            let bytes = match read_bytes(&caller, &memory, ptr, len) {
                Some(b) => b,
                None => return,
            };
            let msg = String::from_utf8_lossy(&bytes);
            match level {
                0 => tracing::trace!(target: "wasm_plugin", "{}", msg),
                1 => tracing::debug!(target: "wasm_plugin", "{}", msg),
                2 => tracing::info!(target: "wasm_plugin", "{}", msg),
                3 => tracing::warn!(target: "wasm_plugin", "{}", msg),
                _ => tracing::error!(target: "wasm_plugin", "{}", msg),
            }
        },
    )?;

    // ── Request inspection ──────────────────────────────────────────────
    linker.func_wrap(
        "lynxx",
        "lynxx_get_request_method",
        |mut caller: Caller<'_, HostContext>, out_ptr: i32, max_len: i32| -> i32 {
            let value = caller.data().method.clone();
            write_string(&mut caller, &value, out_ptr, max_len)
        },
    )?;

    linker.func_wrap(
        "lynxx",
        "lynxx_get_request_path",
        |mut caller: Caller<'_, HostContext>, out_ptr: i32, max_len: i32| -> i32 {
            let value = caller.data().path.clone();
            write_string(&mut caller, &value, out_ptr, max_len)
        },
    )?;

    linker.func_wrap(
        "lynxx",
        "lynxx_get_request_header",
        |mut caller: Caller<'_, HostContext>,
         name_ptr: i32,
         name_len: i32,
         out_ptr: i32,
         out_max: i32|
         -> i32 {
            let memory = match get_memory(&mut caller) {
                Some(m) => m,
                None => return ERR_OUT_OF_BOUNDS,
            };
            let name = match read_string(&caller, &memory, name_ptr, name_len) {
                Ok(s) => s,
                Err(code) => return code,
            };
            let value = HostContext::find_header(&caller.data().request_headers, &name)
                .map(|s| s.to_string());
            match value {
                Some(v) => write_string(&mut caller, &v, out_ptr, out_max),
                None => ERR_NOT_FOUND,
            }
        },
    )?;

    linker.func_wrap(
        "lynxx",
        "lynxx_set_request_header",
        |mut caller: Caller<'_, HostContext>,
         name_ptr: i32,
         name_len: i32,
         val_ptr: i32,
         val_len: i32|
         -> i32 {
            if caller.data().phase != Phase::Request {
                return ERR_WRONG_PHASE;
            }
            let memory = match get_memory(&mut caller) {
                Some(m) => m,
                None => return ERR_OUT_OF_BOUNDS,
            };
            let name = match read_string(&caller, &memory, name_ptr, name_len) {
                Ok(s) => s,
                Err(code) => return code,
            };
            let val = match read_string(&caller, &memory, val_ptr, val_len) {
                Ok(s) => s,
                Err(code) => return code,
            };
            HostContext::set_header(&mut caller.data_mut().request_headers, &name, &val);
            0
        },
    )?;

    linker.func_wrap(
        "lynxx",
        "lynxx_remove_request_header",
        |mut caller: Caller<'_, HostContext>, name_ptr: i32, name_len: i32| -> i32 {
            if caller.data().phase != Phase::Request {
                return ERR_WRONG_PHASE;
            }
            let memory = match get_memory(&mut caller) {
                Some(m) => m,
                None => return ERR_OUT_OF_BOUNDS,
            };
            let name = match read_string(&caller, &memory, name_ptr, name_len) {
                Ok(s) => s,
                Err(code) => return code,
            };
            HostContext::remove_header(&mut caller.data_mut().request_headers, &name);
            0
        },
    )?;

    linker.func_wrap(
        "lynxx",
        "lynxx_get_request_body",
        |mut caller: Caller<'_, HostContext>, out_ptr: i32, max_len: i32| -> i32 {
            let bytes = caller.data().request_body.clone();
            write_bytes(&mut caller, &bytes, out_ptr, max_len)
        },
    )?;

    linker.func_wrap(
        "lynxx",
        "lynxx_set_request_body",
        |mut caller: Caller<'_, HostContext>, ptr: i32, len: i32| -> i32 {
            if caller.data().phase != Phase::Request {
                return ERR_WRONG_PHASE;
            }
            let cap = caller.data().body_max_bytes;
            if len < 0 || (len as usize) > cap {
                return ERR_TOO_LARGE;
            }
            let memory = match get_memory(&mut caller) {
                Some(m) => m,
                None => return ERR_OUT_OF_BOUNDS,
            };
            let bytes = match read_bytes(&caller, &memory, ptr, len) {
                Some(b) => b,
                None => return ERR_OUT_OF_BOUNDS,
            };
            caller.data_mut().request_body = bytes;
            0
        },
    )?;

    // ── Response inspection / mutation ──────────────────────────────────
    linker.func_wrap(
        "lynxx",
        "lynxx_get_response_status",
        |caller: Caller<'_, HostContext>| -> i32 {
            caller
                .data()
                .response_status
                .map(|s| s as i32)
                .unwrap_or(ERR_NOT_FOUND)
        },
    )?;

    linker.func_wrap(
        "lynxx",
        "lynxx_get_response_header",
        |mut caller: Caller<'_, HostContext>,
         name_ptr: i32,
         name_len: i32,
         out_ptr: i32,
         out_max: i32|
         -> i32 {
            let memory = match get_memory(&mut caller) {
                Some(m) => m,
                None => return ERR_OUT_OF_BOUNDS,
            };
            let name = match read_string(&caller, &memory, name_ptr, name_len) {
                Ok(s) => s,
                Err(code) => return code,
            };
            let value = HostContext::find_header(&caller.data().response_headers, &name)
                .map(|s| s.to_string());
            match value {
                Some(v) => write_string(&mut caller, &v, out_ptr, out_max),
                None => ERR_NOT_FOUND,
            }
        },
    )?;

    linker.func_wrap(
        "lynxx",
        "lynxx_set_response_header",
        |mut caller: Caller<'_, HostContext>,
         name_ptr: i32,
         name_len: i32,
         val_ptr: i32,
         val_len: i32|
         -> i32 {
            // Allowed in both phases: a request-phase plugin may want to
            // pre-stage a response header that on_response will see.
            let memory = match get_memory(&mut caller) {
                Some(m) => m,
                None => return ERR_OUT_OF_BOUNDS,
            };
            let name = match read_string(&caller, &memory, name_ptr, name_len) {
                Ok(s) => s,
                Err(code) => return code,
            };
            let val = match read_string(&caller, &memory, val_ptr, val_len) {
                Ok(s) => s,
                Err(code) => return code,
            };
            HostContext::set_header(&mut caller.data_mut().response_headers, &name, &val);
            0
        },
    )?;

    linker.func_wrap(
        "lynxx",
        "lynxx_short_circuit",
        |mut caller: Caller<'_, HostContext>, status: i32, body_ptr: i32, body_len: i32| -> i32 {
            if !(100..=599).contains(&status) {
                return ERR_TOO_LARGE; // reuse — invalid arg
            }
            let cap = caller.data().body_max_bytes;
            if body_len < 0 || (body_len as usize) > cap {
                return ERR_TOO_LARGE;
            }
            let memory = match get_memory(&mut caller) {
                Some(m) => m,
                None => return ERR_OUT_OF_BOUNDS,
            };
            let body = if body_len == 0 {
                Vec::new()
            } else {
                match read_bytes(&caller, &memory, body_ptr, body_len) {
                    Some(b) => b,
                    None => return ERR_OUT_OF_BOUNDS,
                }
            };
            caller.data_mut().short_circuit = Some((status as u16, body));
            0
        },
    )?;

    // ── Identity / config ───────────────────────────────────────────────
    linker.func_wrap(
        "lynxx",
        "lynxx_get_consumer_username",
        |mut caller: Caller<'_, HostContext>, out_ptr: i32, max_len: i32| -> i32 {
            let value = caller.data().consumer.clone();
            match value {
                Some(v) => write_string(&mut caller, &v, out_ptr, max_len),
                None => ERR_NOT_FOUND,
            }
        },
    )?;

    linker.func_wrap(
        "lynxx",
        "lynxx_get_config",
        |mut caller: Caller<'_, HostContext>, out_ptr: i32, max_len: i32| -> i32 {
            let value = caller.data().config_json.clone();
            write_string(&mut caller, &value, out_ptr, max_len)
        },
    )?;

    // ── Time / randomness ───────────────────────────────────────────────
    linker.func_wrap("lynxx", "lynxx_now_unix_millis", || -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    })?;

    linker.func_wrap(
        "lynxx",
        "lynxx_random_bytes",
        |mut caller: Caller<'_, HostContext>, ptr: i32, len: i32| -> i32 {
            if len <= 0 {
                return 0;
            }
            if len as usize > MAX_RANDOM_BYTES {
                // Guest asked for more than we'll ever allocate for this —
                // reject before the host-side `vec![0u8; len]` allocation.
                return ERR_TOO_LARGE;
            }
            // xorshift64 seeded per request from thread_rng. Cheap and
            // good enough for plugin-side jitter / id generation. Guests
            // that need crypto-grade entropy should ask for the host to
            // expose a dedicated function in a future ABI revision.
            let mut s = caller.data().rng_seed;
            let mut buf = vec![0u8; len as usize];
            for chunk in buf.chunks_mut(8) {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                let bytes = s.to_le_bytes();
                for (i, b) in chunk.iter_mut().enumerate() {
                    *b = bytes[i];
                }
            }
            caller.data_mut().rng_seed = s;
            let memory = match get_memory(&mut caller) {
                Some(m) => m,
                None => return ERR_OUT_OF_BOUNDS,
            };
            if memory.write(&mut caller, ptr as usize, &buf).is_err() {
                return ERR_OUT_OF_BOUNDS;
            }
            buf.len() as i32
        },
    )?;

    Ok(())
}

// ── Internal helpers ────────────────────────────────────────────────────

fn get_memory(caller: &mut Caller<'_, HostContext>) -> Option<Memory> {
    match caller.get_export("memory") {
        Some(Extern::Memory(m)) => Some(m),
        _ => None,
    }
}

fn read_bytes(
    caller: &Caller<'_, HostContext>,
    memory: &Memory,
    ptr: i32,
    len: i32,
) -> Option<Vec<u8>> {
    if ptr < 0 || len < 0 {
        return None;
    }
    let ptr = ptr as usize;
    let len = len as usize;
    let data = memory.data(caller);
    if ptr.checked_add(len)? > data.len() {
        return None;
    }
    Some(data[ptr..ptr + len].to_vec())
}

fn read_string(
    caller: &Caller<'_, HostContext>,
    memory: &Memory,
    ptr: i32,
    len: i32,
) -> Result<String, i32> {
    let bytes = read_bytes(caller, memory, ptr, len).ok_or(ERR_OUT_OF_BOUNDS)?;
    String::from_utf8(bytes).map_err(|_| ERR_INVALID_UTF8)
}

fn write_string(
    caller: &mut Caller<'_, HostContext>,
    value: &str,
    out_ptr: i32,
    max_len: i32,
) -> i32 {
    write_bytes(caller, value.as_bytes(), out_ptr, max_len)
}

fn write_bytes(
    caller: &mut Caller<'_, HostContext>,
    bytes: &[u8],
    out_ptr: i32,
    max_len: i32,
) -> i32 {
    if max_len < 0 || out_ptr < 0 {
        return ERR_OUT_OF_BOUNDS;
    }
    if (bytes.len() as i64) > (max_len as i64) {
        return ERR_BUFFER_TOO_SMALL;
    }
    let memory = match get_memory(caller) {
        Some(m) => m,
        None => return ERR_OUT_OF_BOUNDS,
    };
    if memory.write(caller, out_ptr as usize, bytes).is_err() {
        return ERR_OUT_OF_BOUNDS;
    }
    bytes.len() as i32
}
