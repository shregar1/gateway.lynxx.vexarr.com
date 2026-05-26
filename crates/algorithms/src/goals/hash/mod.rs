//! Key and byte hashing — SipHash, Snowflake ID generator.

pub mod siphash;
pub mod snowflake;

pub use siphash::SipHasher;
pub use snowflake::{SnowflakeGenerator, SnowflakeId};
