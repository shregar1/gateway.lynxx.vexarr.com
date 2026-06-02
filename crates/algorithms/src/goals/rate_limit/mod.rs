//! Rate limiting, traffic shaping, and overload control.
//!
//! | Module | Origin | Role |
//! |--------|--------|------|
//! | `freq_ctr` | HAProxy | Lock-free sliding-window frequency counter |
//! | `atomic_token_bucket` | Envoy | CAS token bucket |
//! | `gradient_controller` | Envoy | RTT-gradient concurrency limiter |
//! | `admission_control` | Envoy | Success-rate admission |
//! | `histogram` | ATS | Stepped logarithmic latency histogram |
//! | `ip_reputation` | ATS | Multi-tier sieve-LRU IP reputation |
//! | `dagor` | Paper | Compound priority overload control (WeChat) |
//! | `codel` | Paper | CoDel queue delay management (RFC 8289) |

pub mod histogram;
pub mod ip_reputation;
pub mod admission_control;
pub mod atomic_token_bucket;
pub mod freq_ctr;
pub mod gradient_controller;
pub mod dagor;
pub mod codel;

pub use histogram::Histogram;
pub use ip_reputation::{IpReputation, ReputationLevel, SieveConfig};
pub use admission_control::AdmissionController;
pub use atomic_token_bucket::AtomicTokenBucket;
pub use freq_ctr::FreqCounter;
pub use gradient_controller::{GradientConfig, GradientController};
pub use dagor::{DagorController, RequestPriority};
pub use codel::{CoDel, CoDelDecision};
