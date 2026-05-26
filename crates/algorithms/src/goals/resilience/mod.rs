//! Resilience primitives: cache promotion admission control.

pub mod cache_promote;

pub use cache_promote::{PromotionPolicy, PromotionConfig, PromotionDecision, chance_promote};
