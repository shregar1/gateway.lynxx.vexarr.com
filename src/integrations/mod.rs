//! Outbound clients for Vexarr-internal services.
//!
//! Each submodule wraps one external HTTP API in a typed client. Keep
//! these crates dependency-light — they're called from boot paths and
//! background loops, not the proxy hot path, but they still share the
//! Tokio runtime and shouldn't drag in heavyweight runtime features.
//!
//! Lynxx domain code consumes the [`abstraction`] traits, never the
//! concrete clients. That way swapping keyx for another backend
//! (self-hosted Vault, static-key verifier, test mock) is a `main.rs`
//! change — every other crate stays unchanged.

pub mod abstraction;
pub mod keyx;

pub use abstraction::{AdminPrincipal, HmacVerifier, LicenseVerifier, TokenValidator};
