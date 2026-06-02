//! Shared data structures for the Lynxx gateway.
//!
//! Pure in-memory structures (caches, locks, buffers, heaps) with no I/O.
//! Used directly from hot paths or wrapped by `algorithms` backbone adapters.

pub mod arc_cache;
pub mod bit_array;
pub mod bravo_lock;
pub mod clfus_cache;
pub mod clock_cache;
pub mod s3fifo;
pub mod timer_wheel;
pub mod vm_heap;
pub mod write_buffer;
pub mod wtinylfu;

pub use arc_cache::ArcCache;
pub use bit_array::BitArray;
pub use bravo_lock::{BravoLock, BravoReadGuard, BravoWriteGuard};
pub use clfus_cache::ClfusCache;
pub use clock_cache::ClockCache;
pub use s3fifo::S3FifoCache;
pub use timer_wheel::{TimerHandle, TimerWheel};
pub use vm_heap::VmHeap;
pub use write_buffer::{AggregateWriteBuffer, WriteRef};
pub use wtinylfu::WTinyLfu;
