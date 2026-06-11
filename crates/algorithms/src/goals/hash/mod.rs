//! Key and byte hashing — SipHash, Snowflake ID generator, WT6, SDBM,
//! CRC32c, XXHash.

pub mod crc32c;
pub mod sdbm;
pub mod siphash;
pub mod snowflake;
pub mod wt6;
pub mod xxhash;

pub use crc32c::{crc32c_hash, crc32c_update};
pub use sdbm::sdbm_hash;
pub use siphash::SipHasher;
pub use snowflake::{SnowflakeGenerator, SnowflakeId};
pub use wt6::wt6_hash;
pub use xxhash::{xxh32, xxh64};
