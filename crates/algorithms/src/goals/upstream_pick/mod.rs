//! Upstream / load-balancing pick algorithms.
//!
//! | Module | Origin | Role |
//! |--------|--------|------|
//! | `fwlc` | HAProxy | Fast weighted least connections |
//! | `fwrr` | HAProxy | Fast weighted round robin |
//! | `fas` | HAProxy | First available server |
//! | `chash_bounded` | HAProxy | Consistent hash with bounded loads |
//! | `maglev` | Envoy | Maglev consistent hash |
//! | `edf` | Envoy | Earliest deadline first |
//! | `wrsq` | Envoy | Weighted random selection queue |
//! | `slow_start` | Envoy | Slow-start weight ramp |
//! | `locality_lb` | Envoy | Zone-aware routing |
//! | `priority_lb` | Envoy | Priority-based failover |
//! | `peak_ewma` | linkerd2-proxy | Peak EWMA latency LB |
//! | `completion_tracker` | linkerd2-proxy | Load completion signaling |
//! | `p2c` | Paper | Power of two choices (Mitzenmacher) |

pub mod fwlc;
pub mod fwrr;
pub mod fas;
pub mod chash_bounded;
pub mod maglev;
pub mod edf;
pub mod wrsq;
pub mod slow_start;
pub mod locality_lb;
pub mod priority_lb;
pub mod peak_ewma;
pub mod completion_tracker;
pub mod p2c;

pub use fwlc::FwlcSelector;
pub use fwrr::FwrrSelector;
pub use fas::FasSelector;
pub use chash_bounded::BoundedCHash;
pub use maglev::MaglevTable;
pub use edf::EdfScheduler;
pub use wrsq::WrsqSelector;
pub use slow_start::SlowStartPool;
pub use locality_lb::locality_pick;
pub use priority_lb::PriorityLb;
pub use peak_ewma::PeakEwmaLb;
pub use completion_tracker::CompletionTracker;
pub use p2c::P2cBalancer;
