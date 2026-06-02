//! Rate limiting and traffic shaping algorithms.

pub mod histogram;
pub mod ip_reputation;
pub mod admission_control;
pub mod atomic_token_bucket;
pub mod freq_ctr;
pub mod gradient_controller;
pub mod dagor;
pub mod codel;
