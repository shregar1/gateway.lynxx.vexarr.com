//! Upstream / load-balancing pick algorithms.
//!
//! Twelve strategies drawn from HAProxy, Envoy, and linkerd2-proxy:
//!
//! - **fwlc** — Fast Weighted Least Connections (HAProxy)
//! - **fwrr** — Fast Weighted Round Robin (HAProxy)
//! - **fas** — First Available Server (HAProxy)
//! - **chash_bounded** — Consistent Hash with Bounded Loads (HAProxy)
//! - **maglev** — Maglev consistent hash table (Envoy)
//! - **edf** — Earliest Deadline First scheduler (Envoy)
//! - **wrsq** — Weighted Random Selection Queue (Envoy)
//! - **slow_start** — Slow-start weight ramping (Envoy)
//! - **locality_lb** — Zone-aware routing (Envoy)
//! - **priority_lb** — Priority-based distribution (Envoy)
//! - **peak_ewma** — Peak EWMA latency-based LB (linkerd2-proxy)
//! - **completion_tracker** — Load completion signaling (linkerd2-proxy)

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
