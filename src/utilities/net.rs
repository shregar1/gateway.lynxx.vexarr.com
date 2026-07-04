//! Resilient TCP binding — moved to `utilx::net`.
//!
//! Re-exported / thinly wrapped here so existing call sites
//! (`utilities::resilient_bind`, `utilities::BindConfig`) keep working
//! unchanged.

pub use utilx::net::{BindConfig, BoundListener};

/// Bind a TCP listener with `SO_REUSEADDR`/`SO_REUSEPORT`, retry-with-backoff,
/// and (unless `strict`) OS-assigned-port fallback. Delegates to
/// [`utilx::net::resilient_bind`].
pub async fn resilient_bind(cfg: &BindConfig) -> anyhow::Result<BoundListener> {
    Ok(utilx::net::resilient_bind(cfg).await?)
}
