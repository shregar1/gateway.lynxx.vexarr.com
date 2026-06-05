//! Zero-Trust Runtime Capability Tokens (JWT).
//!
//! Provided by the shared `utilx` crate (`utilx::license::grant`). This module
//! re-exports it for backwards compatibility.

#[allow(unused_imports)] // intentional back-compat re-export surface
pub use utilx::license::grant::{Capability, GrantClaims, GrantManager};
