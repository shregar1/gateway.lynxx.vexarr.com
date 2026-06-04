//! Optimized algorithm variants — drop-in replacements with better performance.
//!
//! Each sub-module provides an optimized version of a high-priority target algorithm.
//! Benchmarks in `benches/optimized/` compare original vs optimized side-by-side.

pub mod huff_decode;
pub mod unescape_uri;
pub mod crc32;
pub mod base64_decode;
pub mod ja4;
pub mod escape_uri;
pub mod snowflake;

pub use snowflake::SnowflakeGeneratorFast;
