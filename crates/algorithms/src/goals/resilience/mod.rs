//! Resilience primitives: cache promotion admission control.

pub mod cache_promote;
pub mod backoff;
pub mod circuit_breaker;
pub mod passive_health;
pub mod retry_budget;
pub mod stampede_lock;
pub mod failfast;

pub use cache_promote::{PromotionPolicy, PromotionConfig, PromotionDecision, chance_promote};
