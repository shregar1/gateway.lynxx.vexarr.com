//! License gating — now provided by the shared `utilx` crate
//! (`utilx::license`), the canonical vexarr license mechanism. This module
//! re-exports the public surface for backwards compatibility — existing
//! `crate::license::*` call sites keep working unchanged.

#[allow(unused_imports)] // intentional back-compat re-export surface
pub use utilx::license::{
    compute_instance_id, deregister_node, register_node, spawn_license_refresher,
    spawn_node_heartbeat, spawn_usage_reporter, License, LicenseError, LicenseState, NodeError,
};
