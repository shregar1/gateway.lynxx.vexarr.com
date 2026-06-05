//! Trait surface for outbound credential / signature services.
//!
//! These types now live in the shared `utilx` crate (`utilx::license::verifier`)
//! so the licence/auth core is reused across vexarr products. Re-exported here
//! for backwards compatibility — existing `crate::integrations::abstraction::*`
//! call sites keep working unchanged.

pub use utilx::license::verifier::{
    AdminPrincipal, HmacVerifier, LicenseInfo, LicenseVerifier, TokenValidator, VerifierError,
};
