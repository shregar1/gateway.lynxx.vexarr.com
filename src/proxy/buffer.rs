//! HAProxy-inspired buffer management for the proxy hot path.
//!
//! # Architecture
//!
//! ```text
//! BufferManager (configurable strategy)
//! ├── RingBuf         — Circular buffer for zero-copy forwarding (HAProxy buf.h)
//! │   ├── write()     — Append at tail (wrapping)
//! │   ├── read()      — Read from head
//! │   ├── xfer()      — Direct buffer-to-buffer transfer (b_xfer)
//! │   └── compact()   — Coalesce fragmented data
//! ├── HeaderBlock     — HTX-style flat header representation
//! │   ├── In-place hop-by-hop removal (zero alloc)
//! │   ├── In-place set/remove (no HeaderMap realloc)
//! │   └── Bidirectional HeaderMap conversion
//! ├── CompactBuf      — Pool-backed linear buffer with consume semantics
//! └── Inline header stripping (zero-alloc direct removal)
//! ```
//!
//! # Why
//!
//! HAProxy's circular buffer (`buf.h`) and HTX representation allow in-place
//! header rewriting without reallocating. `b_xfer()` transfers data between
//! buffers with zero intermediate allocation — the data moves directly from
//! source to destination. Lynxx's original hop-by-hop stripping collected
//! header names into a `Vec`, then removed them — allocating on every
//! request that carried Connection/Upgrade/etc headers.
//!
//! # Strategies (all configurable)
//!
//! | Strategy | Backing | Best for |
//! |----------|---------|----------|
//! | Standard | `Vec<u8>` from system allocator | Debugging, small deployments |
//! | Pooled   | `Vec<u8>` from slab pool | General production use |
//! | Ring     | Circular buffer (pool-backed) | High-throughput with mixed upstreams |
//!
//! | Header Strategy | Method | Best for |
//! |-----------------|--------|----------|
//! | Standard        | Collect + remove (current) | Compatibility, small header counts |
//! | Direct          | Fixed-set `remove()` calls | General production (default) |
//! | Block           | HTX-style flat buffer | Bulk header mutation, plugins |

use crate::proxy::pool;
use std::sync::atomic::{AtomicU8, Ordering};

// ---------------------------------------------------------------------------
// Strategy enums
// ---------------------------------------------------------------------------

/// Body buffer strategy. Stored as `AtomicU8` for lock-free runtime switching.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BufferStrategy {
    /// Standard: `Vec<u8>` from the system allocator. Original behaviour.
    Standard = 0,
    /// Pooled: `Vec<u8>` from the slab pool — near-zero malloc on the hot path.
    Pooled = 1,
    /// Ring: Circular buffer with pool backing for flow-controlled forwarding.
    Ring = 2,
}

impl BufferStrategy {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Pooled,
            2 => Self::Ring,
            _ => Self::Standard,
        }
    }
}

/// Header manipulation strategy.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HeaderStrategy {
    /// Standard: iterate keys → collect matches → remove. Original algorithm.
    Standard = 0,
    /// Direct: call `remove()` for each of the 9 known hop-by-hop headers.
    /// Zero intermediate allocation. Default.
    Direct = 1,
    /// Block: HTX-style flat buffer with in-place deletion/mutation.
    /// Best for bulk header manipulation (many mutations per request).
    Block = 2,
}

impl HeaderStrategy {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Direct,
            2 => Self::Block,
            _ => Self::Standard,
        }
    }
}

/// Global runtime toggles.
static BUFFER_STRATEGY: AtomicU8 = AtomicU8::new(BufferStrategy::Pooled as u8);
static HEADER_STRATEGY: AtomicU8 = AtomicU8::new(HeaderStrategy::Direct as u8);

/// Set the body buffer strategy at runtime.
pub fn set_buffer_strategy(s: BufferStrategy) {
    BUFFER_STRATEGY.store(s as u8, Ordering::Relaxed);
}

/// Set the header manipulation strategy at runtime.
pub fn set_header_strategy(s: HeaderStrategy) {
    HEADER_STRATEGY.store(s as u8, Ordering::Relaxed);
}

pub fn buffer_strategy() -> BufferStrategy {
    BufferStrategy::from_u8(BUFFER_STRATEGY.load(Ordering::Relaxed))
}

pub fn header_strategy() -> HeaderStrategy {
    HeaderStrategy::from_u8(HEADER_STRATEGY.load(Ordering::Relaxed))
}

// ---------------------------------------------------------------------------
// RingBuf — Circular buffer (HAProxy buf.h equivalent)
// ---------------------------------------------------------------------------

/// Circular buffer for zero-copy forwarding. Inspired by HAProxy's `struct
/// buffer` (buf.h) which enables `b_xfer()` — direct buffer-to-buffer
/// transfer without intermediate allocation.
///
/// The ring wraps around: writes go at `(head + len) % cap`, reads come
/// from `head`. When data spans the wrap point, `read_slices()` returns
/// two contiguous slices. `compact()` moves data to offset 0 for callers
/// that need a single contiguous view.
///
/// Backing memory comes from the slab pool when pools are enabled,
/// falling back to the system allocator otherwise.
pub struct RingBuf {
    buf: Vec<u8>,
    cap: usize,
    head: usize,
    len: usize,
}

impl RingBuf {
    /// Create a new ring buffer with the given capacity.
    /// Uses the slab pool if enabled.
    pub fn new(capacity: usize) -> Self {
        let mut buf = if pool::is_enabled() {
            pool::acquire_buf(capacity).into_vec()
        } else {
            Vec::with_capacity(capacity)
        };
        let cap = buf.capacity();
        // Pre-fill to capacity so we can index freely.
        buf.resize(cap, 0);
        Self {
            buf,
            cap,
            head: 0,
            len: 0,
        }
    }

    /// Create a ring buffer with an exact capacity (bypasses pool).
    /// Useful for tests and cases where precise sizing is needed.
    pub fn with_exact_capacity(capacity: usize) -> Self {
        let buf = vec![0u8; capacity];
        let cap = buf.len();
        Self {
            buf,
            cap,
            head: 0,
            len: 0,
        }
    }

    /// Create from an existing pooled buffer.
    pub fn from_pooled(buf: pool::PooledBuf, capacity: usize) -> Self {
        let mut vec = buf.into_vec();
        if vec.capacity() < capacity {
            vec.reserve(capacity - vec.capacity());
        }
        let cap = vec.capacity();
        vec.resize(cap, 0);
        Self {
            buf: vec,
            cap,
            head: 0,
            len: 0,
        }
    }

    /// Bytes of data available to read.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// True if no data is available.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Free space available for writing.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.cap - self.len
    }

    /// Total capacity of the ring.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Write position (one past the last byte of data).
    #[inline]
    fn tail(&self) -> usize {
        (self.head + self.len) % self.cap
    }

    /// Append data at the tail. Returns the number of bytes actually
    /// written (may be less than `data.len()` if the ring is full).
    pub fn write(&mut self, data: &[u8]) -> usize {
        let room = self.remaining();
        let n = data.len().min(room);
        if n == 0 {
            return 0;
        }

        let tail = self.tail();

        if tail + n <= self.cap {
            // Contiguous write — no wrap.
            self.buf[tail..tail + n].copy_from_slice(&data[..n]);
        } else {
            // Split write across the wrap point.
            let first = self.cap - tail;
            self.buf[tail..self.cap].copy_from_slice(&data[..first]);
            self.buf[..n - first].copy_from_slice(&data[first..n]);
        }

        self.len += n;
        n
    }

    /// Read data as up to two contiguous slices (handles wrap-around).
    /// This is the zero-copy read path — no data is moved.
    pub fn read_slices(&self) -> (&[u8], &[u8]) {
        if self.len == 0 {
            return (&[], &[]);
        }

        if self.head + self.len <= self.cap {
            // Data is contiguous.
            (&self.buf[self.head..self.head + self.len], &[])
        } else {
            // Data wraps around.
            let first = &self.buf[self.head..self.cap];
            let second = &self.buf[..self.len - first.len()];
            (first, second)
        }
    }

    /// Advance the read pointer, consuming `n` bytes.
    pub fn consume(&mut self, n: usize) {
        let n = n.min(self.len);
        self.head = (self.head + n) % self.cap;
        self.len -= n;
        if self.len == 0 {
            self.head = 0; // reset for better locality
        }
    }

    /// Move data to the front of the buffer so it's fully contiguous.
    /// No-op if data is already contiguous.
    pub fn compact(&mut self) {
        if self.head == 0 || self.len == 0 {
            return;
        }

        if self.head + self.len <= self.cap {
            // Data is contiguous but not at offset 0.
            self.buf.copy_within(self.head..self.head + self.len, 0);
        } else {
            // Data wraps — need a temporary copy.
            let first_len = self.cap - self.head;
            let second_len = self.len - first_len;
            // Rotate in-place: this handles the wrap correctly.
            self.buf[..self.cap].rotate_left(self.head);
            // After rotation, data starts at 0 and is contiguous.
            let _ = (first_len, second_len); // used by rotation implicitly
        }
        self.head = 0;
    }

    /// Get a contiguous view of all data. Compacts first if needed.
    pub fn as_contiguous(&mut self) -> &[u8] {
        self.compact();
        &self.buf[..self.len]
    }

    /// Consume all data into a `Vec<u8>`.
    pub fn into_vec(mut self) -> Vec<u8> {
        self.compact();
        self.buf.truncate(self.len);
        self.buf
    }

    /// Reset the buffer to empty state without freeing memory.
    pub fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }
}

/// HAProxy-style `b_xfer()`: transfer data directly from `src` to `dst`
/// without any intermediate allocation. Returns the number of bytes
/// transferred.
///
/// This is the core zero-copy forwarding primitive. In HAProxy, `b_xfer`
/// powers the entire data plane — buffers flow from frontend to backend
/// connections with just pointer arithmetic and `memcpy`.
pub fn buf_xfer(src: &mut RingBuf, dst: &mut RingBuf) -> usize {
    let n = src.len().min(dst.remaining());
    if n == 0 {
        return 0;
    }

    let (a, b) = src.read_slices();
    let mut written = 0;

    if !a.is_empty() && written < n {
        let chunk = &a[..a.len().min(n - written)];
        written += dst.write(chunk);
    }
    if !b.is_empty() && written < n {
        let chunk = &b[..b.len().min(n - written)];
        written += dst.write(chunk);
    }

    src.consume(written);
    written
}

// ---------------------------------------------------------------------------
// CompactBuf — Pool-backed linear buffer with consume semantics
// ---------------------------------------------------------------------------

/// Linear buffer with pool backing and consume semantics. Simpler than
/// `RingBuf` for cases where data flows in one direction (collect body
/// chunks → send once). Compacts automatically when the consumed prefix
/// exceeds half the buffer.
///
/// Use `RingBuf` for bidirectional flow-controlled forwarding.
/// Use `CompactBuf` for collect-then-send body buffering.
pub struct CompactBuf {
    inner: Vec<u8>,
    read_pos: usize,
}

impl CompactBuf {
    /// Create with a size hint. Uses the slab pool if enabled.
    pub fn new(size_hint: usize) -> Self {
        let inner = if pool::is_enabled() {
            pool::acquire_buf(size_hint).into_vec()
        } else {
            Vec::with_capacity(size_hint)
        };
        Self {
            inner,
            read_pos: 0,
        }
    }

    /// Append data.
    pub fn write(&mut self, data: &[u8]) {
        self.maybe_compact();
        self.inner.extend_from_slice(data);
    }

    /// Readable data (from read_pos to end).
    pub fn data(&self) -> &[u8] {
        &self.inner[self.read_pos..]
    }

    /// Consume `n` bytes from the front.
    pub fn consume(&mut self, n: usize) {
        self.read_pos = (self.read_pos + n).min(self.inner.len());
        if self.read_pos == self.inner.len() {
            // All data consumed — reset.
            self.inner.clear();
            self.read_pos = 0;
        }
    }

    /// Unconsumed data length.
    pub fn len(&self) -> usize {
        self.inner.len() - self.read_pos
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total bytes written (including consumed).
    pub fn total_written(&self) -> usize {
        self.inner.len()
    }

    /// Compact if the consumed prefix exceeds half the capacity.
    fn maybe_compact(&mut self) {
        if self.read_pos > self.inner.capacity() / 2 && self.read_pos > 0 {
            self.inner.copy_within(self.read_pos.., 0);
            let new_len = self.inner.len() - self.read_pos;
            self.inner.truncate(new_len);
            self.read_pos = 0;
        }
    }

    /// Consume all data into a `Vec<u8>`.
    pub fn into_vec(mut self) -> Vec<u8> {
        if self.read_pos > 0 {
            self.inner.copy_within(self.read_pos.., 0);
            let new_len = self.inner.len() - self.read_pos;
            self.inner.truncate(new_len);
        }
        self.inner
    }

    /// Clear without freeing memory.
    pub fn clear(&mut self) {
        self.inner.clear();
        self.read_pos = 0;
    }
}

// ---------------------------------------------------------------------------
// HeaderBlock — HTX-style flat header representation
// ---------------------------------------------------------------------------

/// Entry tag in the header block.
const TAG_DELETED: u8 = 0x00;
const TAG_ACTIVE: u8 = 0x01;
const TAG_HOP_BY_HOP: u8 = 0x02;

/// Entry header size: [tag: 1][name_len: 4][value_len: 4] = 9 bytes.
///
/// BUG FIX: lengths were previously `u16` (2 bytes each, 5-byte header), which
/// truncated any name/value >= 65536 bytes (large Cookie / JWT Authorization /
/// custom headers — all realistic HTTP inputs). The truncated on-buffer length
/// then no longer matched the bytes actually written, desynchronising the parse
/// walk and causing out-of-bounds slicing panics. Widened to `u32` (4 bytes
/// each) so the stored length always matches the bytes written.
const ENTRY_HEADER_SIZE: usize = 9;

/// Known hop-by-hop header names for pre-tagging.
static BLOCK_HOP_BY_HOP: &[&str] = &[
    "host",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

fn is_hop_by_hop_name(name: &str) -> bool {
    BLOCK_HOP_BY_HOP
        .iter()
        .any(|h| h.eq_ignore_ascii_case(name))
}

/// HTX-inspired flat header block. Headers are stored in a contiguous byte
/// buffer as tagged entries:
///
/// ```text
/// [tag:u8][name_len:u32 LE][value_len:u32 LE][name bytes][value bytes]
/// ```
///
/// This layout enables:
/// - **In-place deletion**: set `tag = 0x00` — no reallocation, no compaction.
/// - **In-place hop-by-hop removal**: entries are pre-tagged `TAG_HOP_BY_HOP`
///   during construction; stripping is a single pass flipping tags to
///   `TAG_DELETED`.
/// - **Single allocation**: all headers in one contiguous buffer.
/// - **Cache-friendly iteration**: linear memory walk.
///
/// HAProxy's HTX format (`htx.h`) uses a similar approach — typed blocks
/// in a linear area with in-place manipulation. Lynxx's `HeaderBlock` is
/// the string-header analog.
pub struct HeaderBlock {
    data: Vec<u8>,
    /// Total entries (including deleted).
    count: usize,
    /// Live (non-deleted) entries.
    live: usize,
}

impl HeaderBlock {
    /// Build a header block from an `axum::http::HeaderMap`.
    /// Hop-by-hop headers are pre-tagged for fast stripping.
    pub fn from_header_map(map: &axum::http::HeaderMap) -> Self {
        // Estimate buffer size: 5 bytes overhead + avg ~40 bytes per header.
        let estimated = map.len() * 45;
        let mut data = Vec::with_capacity(estimated);
        let mut count = 0;

        for (name, value) in map.iter() {
            let name_bytes = name.as_str().as_bytes();
            let value_bytes = value.as_bytes();
            // BUG FIX: widened from `u16` (which truncated >= 64 KiB headers and
            // corrupted the buffer) to `u32`, matching ENTRY_HEADER_SIZE = 9.
            let name_len = name_bytes.len() as u32;
            let value_len = value_bytes.len() as u32;

            let tag = if is_hop_by_hop_name(name.as_str()) {
                TAG_HOP_BY_HOP
            } else {
                TAG_ACTIVE
            };

            data.push(tag);
            data.extend_from_slice(&name_len.to_le_bytes());
            data.extend_from_slice(&value_len.to_le_bytes());
            data.extend_from_slice(name_bytes);
            data.extend_from_slice(value_bytes);
            count += 1;
        }

        Self {
            data,
            count,
            live: count,
        }
    }

    /// Build an empty block.
    pub fn empty() -> Self {
        Self {
            data: Vec::new(),
            count: 0,
            live: 0,
        }
    }

    /// Number of live (non-deleted) headers.
    pub fn len(&self) -> usize {
        self.live
    }

    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// Strip all hop-by-hop headers in a single pass. O(N) with zero
    /// allocation — just flips tag bytes from `TAG_HOP_BY_HOP` to
    /// `TAG_DELETED`.
    pub fn strip_hop_by_hop(&mut self) -> usize {
        let mut removed = 0;
        let mut pos = 0;
        while pos + ENTRY_HEADER_SIZE <= self.data.len() {
            let tag = self.data[pos];
            // BUG FIX: lengths are now u32 (4 bytes each, see ENTRY_HEADER_SIZE).
            let name_len = u32::from_le_bytes([
                self.data[pos + 1],
                self.data[pos + 2],
                self.data[pos + 3],
                self.data[pos + 4],
            ]) as usize;
            let value_len = u32::from_le_bytes([
                self.data[pos + 5],
                self.data[pos + 6],
                self.data[pos + 7],
                self.data[pos + 8],
            ]) as usize;
            let entry_size = ENTRY_HEADER_SIZE + name_len + value_len;

            // BUG FIX: bail out if a (malformed/desynced) entry would run past
            // the buffer, so a corrupt block degrades safely instead of panicking.
            if pos + entry_size > self.data.len() {
                break;
            }

            if tag == TAG_HOP_BY_HOP {
                self.data[pos] = TAG_DELETED;
                self.live -= 1;
                removed += 1;
            }

            pos += entry_size;
        }
        removed
    }

    /// Remove all headers with the given name (case-insensitive).
    /// Returns the number of entries removed.
    pub fn remove(&mut self, name: &str) -> usize {
        let mut removed = 0;
        let mut pos = 0;
        while pos + ENTRY_HEADER_SIZE <= self.data.len() {
            let tag = self.data[pos];
            // BUG FIX: lengths are now u32 (4 bytes each, see ENTRY_HEADER_SIZE).
            let name_len = u32::from_le_bytes([
                self.data[pos + 1],
                self.data[pos + 2],
                self.data[pos + 3],
                self.data[pos + 4],
            ]) as usize;
            let value_len = u32::from_le_bytes([
                self.data[pos + 5],
                self.data[pos + 6],
                self.data[pos + 7],
                self.data[pos + 8],
            ]) as usize;
            let entry_size = ENTRY_HEADER_SIZE + name_len + value_len;

            // BUG FIX: stop on a desynced/oversized entry rather than slicing OOB.
            if pos + entry_size > self.data.len() {
                break;
            }

            if tag != TAG_DELETED {
                let entry_name = &self.data[pos + ENTRY_HEADER_SIZE..pos + ENTRY_HEADER_SIZE + name_len];
                if entry_name.eq_ignore_ascii_case(name.as_bytes()) {
                    self.data[pos] = TAG_DELETED;
                    self.live -= 1;
                    removed += 1;
                }
            }

            pos += entry_size;
        }
        removed
    }

    /// Set a header value. If the header exists, it's marked deleted and
    /// a new entry is appended. If not, a new entry is appended.
    pub fn set(&mut self, name: &str, value: &[u8]) {
        self.remove(name);
        let name_bytes = name.as_bytes();
        // BUG FIX: widened from `u16` to `u32` (see ENTRY_HEADER_SIZE) so large
        // names/values are not truncated and the buffer stays consistent.
        let name_len = name_bytes.len() as u32;
        let value_len = value.len() as u32;

        self.data.push(TAG_ACTIVE);
        self.data.extend_from_slice(&name_len.to_le_bytes());
        self.data.extend_from_slice(&value_len.to_le_bytes());
        self.data.extend_from_slice(name_bytes);
        self.data.extend_from_slice(value);
        self.count += 1;
        self.live += 1;
    }

    /// Iterate over all live (non-deleted) header entries.
    pub fn iter(&self) -> HeaderBlockIter<'_> {
        HeaderBlockIter {
            data: &self.data,
            pos: 0,
        }
    }

    /// Convert back to an `axum::http::HeaderMap`.
    pub fn into_header_map(self) -> axum::http::HeaderMap {
        let mut map = axum::http::HeaderMap::with_capacity(self.live);
        for (name, value) in self.iter() {
            if let (Ok(hn), Ok(hv)) = (
                axum::http::header::HeaderName::from_bytes(name),
                axum::http::header::HeaderValue::from_bytes(value),
            ) {
                // BUG FIX: previously used `map.insert`, which drops all prior
                // values for a name — silently discarding every value but the
                // last for multi-valued headers (Set-Cookie, Via, etc.).
                // `append` preserves existing values, matching the multi-entry
                // storage of HeaderBlock so duplicates survive the round-trip.
                map.append(hn, hv);
            }
        }
        map
    }

    /// Remove deleted entries, compacting the buffer.
    pub fn compact(&mut self) {
        if self.live == self.count {
            return; // nothing to compact
        }
        let mut write_pos = 0;
        let mut read_pos = 0;
        while read_pos + ENTRY_HEADER_SIZE <= self.data.len() {
            let tag = self.data[read_pos];
            // BUG FIX: lengths are now u32 (4 bytes each, see ENTRY_HEADER_SIZE).
            let name_len = u32::from_le_bytes([
                self.data[read_pos + 1],
                self.data[read_pos + 2],
                self.data[read_pos + 3],
                self.data[read_pos + 4],
            ]) as usize;
            let value_len = u32::from_le_bytes([
                self.data[read_pos + 5],
                self.data[read_pos + 6],
                self.data[read_pos + 7],
                self.data[read_pos + 8],
            ]) as usize;
            let entry_size = ENTRY_HEADER_SIZE + name_len + value_len;

            // BUG FIX: stop on a desynced/oversized entry rather than slicing OOB.
            if read_pos + entry_size > self.data.len() {
                break;
            }

            if tag != TAG_DELETED {
                if write_pos != read_pos {
                    self.data.copy_within(read_pos..read_pos + entry_size, write_pos);
                }
                write_pos += entry_size;
            }

            read_pos += entry_size;
        }
        self.data.truncate(write_pos);
        self.count = self.live;
    }
}

/// Iterator over live entries in a `HeaderBlock`.
pub struct HeaderBlockIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for HeaderBlockIter<'a> {
    /// `(name_bytes, value_bytes)` — borrowed from the block's buffer.
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.pos + ENTRY_HEADER_SIZE > self.data.len() {
                return None;
            }
            let tag = self.data[self.pos];
            // BUG FIX: lengths are now u32 (4 bytes each, see ENTRY_HEADER_SIZE).
            let name_len = u32::from_le_bytes([
                self.data[self.pos + 1],
                self.data[self.pos + 2],
                self.data[self.pos + 3],
                self.data[self.pos + 4],
            ]) as usize;
            let value_len = u32::from_le_bytes([
                self.data[self.pos + 5],
                self.data[self.pos + 6],
                self.data[self.pos + 7],
                self.data[self.pos + 8],
            ]) as usize;
            let entry_size = ENTRY_HEADER_SIZE + name_len + value_len;

            let name_start = self.pos + ENTRY_HEADER_SIZE;
            let value_start = name_start + name_len;

            // BUG FIX: stop iterating if a desynced/oversized entry would slice
            // past the buffer end, rather than panicking the worker.
            if value_start + value_len > self.data.len() {
                return None;
            }

            self.pos += entry_size;

            if tag != TAG_DELETED {
                return Some((
                    &self.data[name_start..name_start + name_len],
                    &self.data[value_start..value_start + value_len],
                ));
            }
            // Deleted entry — skip.
        }
    }
}

// ---------------------------------------------------------------------------
// Inline hop-by-hop stripping (zero-alloc, works with HeaderMap directly)
// ---------------------------------------------------------------------------

/// Known hop-by-hop headers as `HeaderName` constants — interned at load
/// time, zero runtime parsing.
use axum::http::header::HeaderName;

static DIRECT_HOP_BY_HOP: [HeaderName; 9] = [
    HeaderName::from_static("host"),
    HeaderName::from_static("connection"),
    HeaderName::from_static("keep-alive"),
    HeaderName::from_static("proxy-authenticate"),
    HeaderName::from_static("proxy-authorization"),
    HeaderName::from_static("te"),
    HeaderName::from_static("trailers"),
    HeaderName::from_static("transfer-encoding"),
    HeaderName::from_static("upgrade"),
];

/// Strip hop-by-hop headers by directly removing the 9 known entries.
/// **Zero allocation** — no intermediate `Vec<HeaderName>`, no iteration
/// over all headers. Just 9 hash probes into the `HeaderMap`.
///
/// This is the "Direct" strategy. HAProxy doesn't need even this because
/// its HTX format pre-tags hop-by-hop entries during parsing; Lynxx's
/// `HeaderBlock::strip_hop_by_hop()` mirrors that approach.
///
/// Compared to the "Standard" strategy (iterate all keys → collect matches
/// → remove), this avoids:
/// 1. The `Vec<HeaderName>` allocation (even when empty, the stack frame
///    is larger due to the `Vec` inline metadata).
/// 2. The `name.clone()` for each matching header.
/// 3. The second pass over collected names.
///
/// Trade-off: always does 9 probes even if the map has zero hop-by-hop
/// headers. For maps with < ~50 headers (the vast majority), 9 probes
/// is faster than iterating all keys.
#[inline]
pub fn strip_hop_by_hop_direct(headers: &mut axum::http::HeaderMap) {
    for name in &DIRECT_HOP_BY_HOP {
        headers.remove(name);
    }
}

/// Dispatching strip function that uses the configured header strategy.
///
/// - `Standard`: iterate keys, collect matches, remove (original algorithm).
/// - `Direct`: 9 direct `remove()` calls (default, zero-alloc).
/// - `Block`: Convert to `HeaderBlock`, strip in-place, convert back.
///   Only worth it when combined with other block-level mutations.
#[inline]
pub fn strip_hop_by_hop(headers: &mut axum::http::HeaderMap) {
    match header_strategy() {
        HeaderStrategy::Standard => strip_hop_by_hop_standard(headers),
        HeaderStrategy::Direct => strip_hop_by_hop_direct(headers),
        HeaderStrategy::Block => strip_hop_by_hop_block(headers),
    }
}

/// Standard strategy: iterate keys, collect matches, remove.
/// This is the original Lynxx algorithm — preserved for configurability.
fn strip_hop_by_hop_standard(headers: &mut axum::http::HeaderMap) {
    let mut to_remove: Vec<HeaderName> = Vec::new();
    for name in headers.keys() {
        if DIRECT_HOP_BY_HOP.iter().any(|h| h == name) {
            to_remove.push(name.clone());
        }
    }
    for name in &to_remove {
        headers.remove(name);
    }
}

/// Block strategy: convert to HeaderBlock, strip, convert back.
fn strip_hop_by_hop_block(headers: &mut axum::http::HeaderMap) {
    let mut block = HeaderBlock::from_header_map(headers);
    block.strip_hop_by_hop();
    *headers = block.into_header_map();
}

// ---------------------------------------------------------------------------
// Buffer acquisition helpers (dispatch based on strategy)
// ---------------------------------------------------------------------------

/// Acquire a body buffer using the configured strategy.
///
/// - `Standard`: plain `Vec::with_capacity(hint)`.
/// - `Pooled`: slab-pool-backed `Vec<u8>` via `pool::acquire_buf()`.
/// - `Ring`: `RingBuf::new(hint)`.
///
/// For the `Standard` and `Pooled` strategies, the returned enum wraps a
/// `Vec<u8>`. For `Ring`, it wraps a `RingBuf`.
pub enum BodyBuf {
    /// Standard or pooled linear buffer.
    Linear(Vec<u8>),
    /// Pooled linear buffer (returned to pool on drop via PooledBuf).
    Pooled(pool::PooledBuf),
    /// Circular ring buffer.
    Ring(RingBuf),
}

impl BodyBuf {
    /// Acquire a body buffer with the configured strategy.
    pub fn acquire(size_hint: usize) -> Self {
        match buffer_strategy() {
            BufferStrategy::Standard => Self::Linear(Vec::with_capacity(size_hint)),
            BufferStrategy::Pooled => Self::Pooled(pool::acquire_buf(size_hint)),
            BufferStrategy::Ring => Self::Ring(RingBuf::new(size_hint)),
        }
    }

    /// Append data to the buffer.
    pub fn write(&mut self, data: &[u8]) {
        match self {
            Self::Linear(v) => v.extend_from_slice(data),
            Self::Pooled(v) => v.extend_from_slice(data),
            Self::Ring(r) => {
                r.write(data);
            }
        }
    }

    /// Consume into a `Vec<u8>` for interop with axum/hyper.
    pub fn into_vec(self) -> Vec<u8> {
        match self {
            Self::Linear(v) => v,
            Self::Pooled(p) => p.into_vec(),
            Self::Ring(r) => r.into_vec(),
        }
    }

    /// Current data length.
    pub fn len(&self) -> usize {
        match self {
            Self::Linear(v) => v.len(),
            Self::Pooled(v) => v.len(),
            Self::Ring(r) => r.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── RingBuf ──

    #[test]
    fn ring_write_and_read() {
        let mut ring = RingBuf::new(16);
        assert_eq!(ring.len(), 0);
        assert!(ring.is_empty());

        let n = ring.write(b"hello");
        assert_eq!(n, 5);
        assert_eq!(ring.len(), 5);

        let (a, b) = ring.read_slices();
        assert_eq!(a, b"hello");
        assert!(b.is_empty());
    }

    #[test]
    fn ring_wrap_around() {
        let mut ring = RingBuf::with_exact_capacity(16);
        let cap = ring.capacity();
        assert_eq!(cap, 16);

        // Fill most of the buffer (14 bytes).
        let fill = cap - 2;
        let data: Vec<u8> = (0..fill as u8).collect();
        ring.write(&data);
        assert_eq!(ring.len(), fill);

        // Consume the first half (7 bytes).
        let half = fill / 2;
        ring.consume(half);
        assert_eq!(ring.len(), fill - half);

        // Write more data — this wraps around.
        let extra = vec![0xAA; half + 2];
        let written = ring.write(&extra);
        assert!(written > 0);

        // Data should span the wrap point.
        let (a, b) = ring.read_slices();
        assert_eq!(a.len() + b.len(), ring.len());
        // With a 16-byte buffer, writing past the end wraps to the beginning.
        assert!(!b.is_empty(), "expected wrap-around with two slices");
    }

    #[test]
    fn ring_compact() {
        let mut ring = RingBuf::new(16);
        ring.write(b"ABCDEF");
        ring.consume(3);
        assert_eq!(ring.len(), 3);

        let contiguous = ring.as_contiguous();
        assert_eq!(contiguous, b"DEF");
    }

    #[test]
    fn ring_full_and_empty() {
        let mut ring = RingBuf::with_exact_capacity(8);
        let cap = ring.capacity();

        // Fill to capacity.
        let data: Vec<u8> = vec![42; cap];
        let written = ring.write(&data);
        assert_eq!(written, cap);
        assert_eq!(ring.remaining(), 0);

        // Try to write more — should return 0.
        assert_eq!(ring.write(b"x"), 0);

        // Consume everything.
        ring.consume(cap);
        assert!(ring.is_empty());
        assert_eq!(ring.remaining(), cap);
    }

    #[test]
    fn ring_into_vec() {
        let mut ring = RingBuf::new(32);
        ring.write(b"hello world");
        ring.consume(6);
        let vec = ring.into_vec();
        assert_eq!(&vec, b"world");
    }

    // ── buf_xfer ──

    #[test]
    fn xfer_basic() {
        let mut src = RingBuf::new(32);
        let mut dst = RingBuf::new(32);

        src.write(b"transfer this data");
        let n = buf_xfer(&mut src, &mut dst);
        assert_eq!(n, 18);
        assert!(src.is_empty());

        let vec = dst.into_vec();
        assert_eq!(&vec, b"transfer this data");
    }

    #[test]
    fn xfer_partial() {
        let mut src = RingBuf::with_exact_capacity(32);
        let mut dst = RingBuf::with_exact_capacity(8); // small destination
        let dst_cap = dst.capacity();
        assert_eq!(dst_cap, 8);

        src.write(b"this is a longer message");
        let n = buf_xfer(&mut src, &mut dst);
        assert_eq!(n, dst_cap);
        assert_eq!(src.len(), 24 - dst_cap);
    }

    #[test]
    fn xfer_empty_src() {
        let mut src = RingBuf::new(16);
        let mut dst = RingBuf::new(16);
        assert_eq!(buf_xfer(&mut src, &mut dst), 0);
    }

    // ── CompactBuf ──

    #[test]
    fn compact_buf_write_and_read() {
        let mut buf = CompactBuf::new(64);
        buf.write(b"hello ");
        buf.write(b"world");
        assert_eq!(buf.data(), b"hello world");
        assert_eq!(buf.len(), 11);
    }

    #[test]
    fn compact_buf_consume() {
        let mut buf = CompactBuf::new(64);
        buf.write(b"ABCDEF");
        buf.consume(3);
        assert_eq!(buf.data(), b"DEF");
        assert_eq!(buf.len(), 3);
    }

    #[test]
    fn compact_buf_auto_compact() {
        let mut buf = CompactBuf::new(16);
        buf.write(b"AABBCCDD"); // 8 bytes
        buf.consume(6); // read_pos = 6, remaining = "DD"
        // Write more — should trigger compaction since read_pos > cap/2.
        buf.write(b"EEFFGGHH");
        assert!(buf.data().starts_with(b"DD"));
        assert!(buf.data().ends_with(b"EEFFGGHH"));
    }

    #[test]
    fn compact_buf_into_vec() {
        let mut buf = CompactBuf::new(32);
        buf.write(b"XXYYZZWW");
        buf.consume(4);
        let vec = buf.into_vec();
        assert_eq!(&vec, b"ZZWW");
    }

    // ── HeaderBlock ──

    #[test]
    fn header_block_from_map_roundtrip() {
        let mut map = axum::http::HeaderMap::new();
        map.insert("content-type", "application/json".parse().unwrap());
        map.insert("x-request-id", "abc-123".parse().unwrap());

        let block = HeaderBlock::from_header_map(&map);
        assert_eq!(block.len(), 2);

        let map2 = block.into_header_map();
        assert_eq!(map2.get("content-type").unwrap(), "application/json");
        assert_eq!(map2.get("x-request-id").unwrap(), "abc-123");
    }

    #[test]
    fn header_block_strip_hop_by_hop() {
        let mut map = axum::http::HeaderMap::new();
        map.insert("content-type", "text/html".parse().unwrap());
        map.insert("connection", "keep-alive".parse().unwrap());
        map.insert("transfer-encoding", "chunked".parse().unwrap());
        map.insert("x-custom", "value".parse().unwrap());

        let mut block = HeaderBlock::from_header_map(&map);
        assert_eq!(block.len(), 4);

        let removed = block.strip_hop_by_hop();
        assert_eq!(removed, 2);
        assert_eq!(block.len(), 2);

        let map2 = block.into_header_map();
        assert!(map2.get("connection").is_none());
        assert!(map2.get("transfer-encoding").is_none());
        assert_eq!(map2.get("content-type").unwrap(), "text/html");
        assert_eq!(map2.get("x-custom").unwrap(), "value");
    }

    #[test]
    fn header_block_set_and_remove() {
        let mut block = HeaderBlock::empty();
        block.set("content-type", b"text/plain");
        block.set("x-foo", b"bar");
        assert_eq!(block.len(), 2);

        // Overwrite.
        block.set("content-type", b"application/json");
        assert_eq!(block.len(), 2);
        let map = block.into_header_map();
        assert_eq!(map.get("content-type").unwrap(), "application/json");
    }

    #[test]
    fn header_block_remove_by_name() {
        let mut block = HeaderBlock::empty();
        block.set("a", b"1");
        block.set("b", b"2");
        block.set("c", b"3");
        assert_eq!(block.len(), 3);

        assert_eq!(block.remove("b"), 1);
        assert_eq!(block.len(), 2);

        let entries: Vec<_> = block.iter().collect();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|(n, _)| n != b"b"));
    }

    #[test]
    fn header_block_compact() {
        let mut block = HeaderBlock::empty();
        block.set("a", b"1");
        block.set("b", b"2");
        block.set("c", b"3");
        block.remove("b");

        let before_len = block.data.len();
        block.compact();
        assert!(block.data.len() < before_len);
        assert_eq!(block.len(), 2);
        assert_eq!(block.count, 2);
    }

    #[test]
    fn header_block_iterate_skips_deleted() {
        let mut block = HeaderBlock::empty();
        block.set("keep", b"yes");
        block.set("delete-me", b"no");
        block.set("also-keep", b"yes");
        block.remove("delete-me");

        let names: Vec<&[u8]> = block.iter().map(|(n, _)| n).collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&b"keep".as_ref()));
        assert!(names.contains(&b"also-keep".as_ref()));
    }

    // ── Direct hop-by-hop stripping ──

    #[test]
    fn direct_strip_removes_known_headers() {
        let mut map = axum::http::HeaderMap::new();
        map.insert("content-type", "text/html".parse().unwrap());
        map.insert("connection", "keep-alive".parse().unwrap());
        map.insert("keep-alive", "timeout=5".parse().unwrap());
        map.insert("transfer-encoding", "chunked".parse().unwrap());
        map.insert("x-custom", "preserved".parse().unwrap());

        strip_hop_by_hop_direct(&mut map);

        assert!(map.get("connection").is_none());
        assert!(map.get("keep-alive").is_none());
        assert!(map.get("transfer-encoding").is_none());
        assert_eq!(map.get("content-type").unwrap(), "text/html");
        assert_eq!(map.get("x-custom").unwrap(), "preserved");
    }

    #[test]
    fn direct_strip_no_headers_noop() {
        let mut map = axum::http::HeaderMap::new();
        map.insert("content-type", "text/html".parse().unwrap());
        map.insert("x-custom", "value".parse().unwrap());

        strip_hop_by_hop_direct(&mut map);

        assert_eq!(map.len(), 2);
    }

    // ── Strategy dispatch ──

    #[test]
    fn strategy_dispatch_strip() {
        // Test all three strategies produce the same result.
        let make_map = || {
            let mut map = axum::http::HeaderMap::new();
            map.insert("content-type", "text/html".parse().unwrap());
            map.insert("connection", "close".parse().unwrap());
            map.insert("x-custom", "val".parse().unwrap());
            map
        };

        for strategy in [HeaderStrategy::Standard, HeaderStrategy::Direct, HeaderStrategy::Block] {
            HEADER_STRATEGY.store(strategy as u8, Ordering::Relaxed);
            let mut map = make_map();
            strip_hop_by_hop(&mut map);

            assert!(map.get("connection").is_none(), "strategy {:?} failed", strategy);
            assert_eq!(map.get("content-type").unwrap(), "text/html");
            assert_eq!(map.get("x-custom").unwrap(), "val");
        }

        // Reset to default.
        HEADER_STRATEGY.store(HeaderStrategy::Direct as u8, Ordering::Relaxed);
    }

    // ── BodyBuf ──

    #[test]
    fn body_buf_standard() {
        BUFFER_STRATEGY.store(BufferStrategy::Standard as u8, Ordering::Relaxed);
        let mut buf = BodyBuf::acquire(64);
        buf.write(b"hello");
        assert_eq!(buf.len(), 5);
        let vec = buf.into_vec();
        assert_eq!(&vec, b"hello");
        BUFFER_STRATEGY.store(BufferStrategy::Pooled as u8, Ordering::Relaxed);
    }

    #[test]
    fn body_buf_pooled() {
        BUFFER_STRATEGY.store(BufferStrategy::Pooled as u8, Ordering::Relaxed);
        let mut buf = BodyBuf::acquire(128);
        buf.write(b"pooled data");
        assert_eq!(buf.len(), 11);
        let vec = buf.into_vec();
        assert_eq!(&vec, b"pooled data");
    }

    #[test]
    fn body_buf_ring() {
        BUFFER_STRATEGY.store(BufferStrategy::Ring as u8, Ordering::Relaxed);
        let mut buf = BodyBuf::acquire(64);
        buf.write(b"ring buffer data");
        assert_eq!(buf.len(), 16);
        let vec = buf.into_vec();
        assert_eq!(&vec, b"ring buffer data");
        BUFFER_STRATEGY.store(BufferStrategy::Pooled as u8, Ordering::Relaxed);
    }

    #[test]
    fn buffer_strategy_toggle() {
        set_buffer_strategy(BufferStrategy::Standard);
        assert_eq!(buffer_strategy(), BufferStrategy::Standard);
        set_buffer_strategy(BufferStrategy::Pooled);
        assert_eq!(buffer_strategy(), BufferStrategy::Pooled);
        set_buffer_strategy(BufferStrategy::Ring);
        assert_eq!(buffer_strategy(), BufferStrategy::Ring);
    }

    #[test]
    fn header_strategy_toggle() {
        set_header_strategy(HeaderStrategy::Standard);
        assert_eq!(header_strategy(), HeaderStrategy::Standard);
        set_header_strategy(HeaderStrategy::Direct);
        assert_eq!(header_strategy(), HeaderStrategy::Direct);
        set_header_strategy(HeaderStrategy::Block);
        assert_eq!(header_strategy(), HeaderStrategy::Block);
    }

    // ── RingBuf: available_read / available_write / is_full / is_empty ──

    #[test]
    fn ring_available_read_write_after_operations() {
        let mut ring = RingBuf::with_exact_capacity(16);
        assert_eq!(ring.len(), 0);
        assert_eq!(ring.remaining(), 16);
        assert!(ring.is_empty());

        ring.write(b"abcde");
        assert_eq!(ring.len(), 5);        // available_read
        assert_eq!(ring.remaining(), 11); // available_write

        ring.consume(3);
        assert_eq!(ring.len(), 2);
        assert_eq!(ring.remaining(), 14);

        ring.write(b"fghij");
        assert_eq!(ring.len(), 7);
        assert_eq!(ring.remaining(), 9);
    }

    #[test]
    fn ring_is_full() {
        let mut ring = RingBuf::with_exact_capacity(4);
        assert_eq!(ring.remaining(), 4);
        ring.write(b"ABCD");
        assert_eq!(ring.remaining(), 0);
        assert_eq!(ring.len(), 4);
    }

    #[test]
    fn ring_is_empty_after_consume_all() {
        let mut ring = RingBuf::with_exact_capacity(8);
        ring.write(b"data");
        assert!(!ring.is_empty());
        ring.consume(4);
        assert!(ring.is_empty());
        assert_eq!(ring.remaining(), 8);
    }

    #[test]
    fn ring_wrap_around_write_and_read_correctness() {
        let mut ring = RingBuf::with_exact_capacity(8);
        // Write 6, consume 4 → head=4, len=2, tail=6
        ring.write(b"ABCDEF");
        ring.consume(4);
        assert_eq!(ring.len(), 2);

        // Write 5 more → tail wraps: 6+5=11, 11%8=3
        let n = ring.write(b"GHIJK");
        assert_eq!(n, 5);
        assert_eq!(ring.len(), 7);

        // Verify two-slice read
        let (a, b) = ring.read_slices();
        assert_eq!(a.len() + b.len(), 7);
        let mut all = a.to_vec();
        all.extend_from_slice(b);
        assert_eq!(&all, b"EFGHIJK");
    }

    #[test]
    fn ring_try_write_when_full_returns_zero() {
        let mut ring = RingBuf::with_exact_capacity(4);
        ring.write(b"FULL");
        assert_eq!(ring.remaining(), 0);
        let n = ring.write(b"X");
        assert_eq!(n, 0);
        assert_eq!(ring.len(), 4);
    }

    #[test]
    fn ring_peek_returns_data_without_consuming() {
        let mut ring = RingBuf::with_exact_capacity(16);
        ring.write(b"peek test");
        let (a, b) = ring.read_slices();
        let mut peeked = a.to_vec();
        peeked.extend_from_slice(b);
        assert_eq!(&peeked, b"peek test");
        // Data is still there — not consumed.
        assert_eq!(ring.len(), 9);
        let (a2, _) = ring.read_slices();
        assert_eq!(a2, b"peek test");
    }

    #[test]
    fn ring_consume_more_than_available_clamps() {
        let mut ring = RingBuf::with_exact_capacity(8);
        ring.write(b"ABC");
        ring.consume(100); // more than len=3
        assert!(ring.is_empty());
        assert_eq!(ring.len(), 0);
    }

    #[test]
    fn ring_compact_wrap_around() {
        let mut ring = RingBuf::with_exact_capacity(8);
        // Force wrap: write 6, consume 5 → head=5, len=1
        ring.write(b"ABCDEF");
        ring.consume(5);
        // Write 5 more → wraps around
        ring.write(b"GHIJK");
        assert_eq!(ring.len(), 6); // F + GHIJK

        let contiguous = ring.as_contiguous();
        assert_eq!(contiguous, b"FGHIJK");
    }

    #[test]
    fn ring_clear() {
        let mut ring = RingBuf::with_exact_capacity(16);
        ring.write(b"some data");
        ring.clear();
        assert!(ring.is_empty());
        assert_eq!(ring.remaining(), 16);
    }

    // ── CompactBuf: capacity, len, is_empty, consume partial, reset ──

    #[test]
    fn compact_buf_is_empty() {
        let buf = CompactBuf::new(32);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn compact_buf_consume_partial() {
        let mut buf = CompactBuf::new(64);
        buf.write(b"ABCDEFGHIJ"); // 10 bytes
        buf.consume(4);
        assert_eq!(buf.len(), 6);
        assert_eq!(buf.data(), b"EFGHIJ");
        buf.consume(3);
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.data(), b"HIJ");
    }

    #[test]
    fn compact_buf_consume_all_resets() {
        let mut buf = CompactBuf::new(64);
        buf.write(b"ABCDEF");
        buf.consume(6); // consume exactly all
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        // After full consume, internal state resets — write fresh data.
        buf.write(b"GH");
        assert_eq!(buf.data(), b"GH");
    }

    #[test]
    fn compact_buf_auto_compact_trigger() {
        // Create a small-capacity buffer to trigger compaction easily.
        let mut buf = CompactBuf::new(8);
        // Write 8 bytes (fills capacity).
        buf.write(b"AAAABBBB");
        // Consume 5 bytes → read_pos=5, capacity/2 = at least 4, so 5 > cap/2.
        buf.consume(5);
        assert_eq!(buf.data(), b"BBB");

        // Next write triggers maybe_compact.
        buf.write(b"CC");
        assert_eq!(buf.data(), b"BBBCC");
        // Verify total_written reflects the compaction (internal length).
        assert_eq!(buf.len(), 5);
    }

    #[test]
    fn compact_buf_clear() {
        let mut buf = CompactBuf::new(32);
        buf.write(b"ABCDEF");
        buf.consume(2);
        buf.clear();
        assert!(buf.is_empty());
        assert_eq!(buf.total_written(), 0);
    }

    #[test]
    fn compact_buf_total_written() {
        let mut buf = CompactBuf::new(64);
        buf.write(b"ABC");
        buf.write(b"DEF");
        assert_eq!(buf.total_written(), 6);
        buf.consume(3);
        // total_written still reflects total inner len.
        assert_eq!(buf.total_written(), 6);
    }

    // ── HeaderBlock: get, set overwrite, remove non-existent, iter order, len after removes, compact reclaims, from_map empty ──

    #[test]
    fn header_block_get_returns_correct_value() {
        let mut block = HeaderBlock::empty();
        block.set("content-type", b"text/html");
        block.set("x-request-id", b"r-42");

        let entries: Vec<_> = block.iter().collect();
        let ct = entries.iter().find(|(n, _)| *n == b"content-type");
        assert!(ct.is_some());
        assert_eq!(ct.unwrap().1, b"text/html");
    }

    #[test]
    fn header_block_set_overwrites_existing() {
        let mut block = HeaderBlock::empty();
        block.set("key", b"old-value");
        block.set("key", b"new-value");
        assert_eq!(block.len(), 1);

        let entries: Vec<_> = block.iter().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, b"new-value");
    }

    #[test]
    fn header_block_remove_nonexistent_key() {
        let mut block = HeaderBlock::empty();
        block.set("a", b"1");
        let removed = block.remove("nonexistent");
        assert_eq!(removed, 0);
        assert_eq!(block.len(), 1);
    }

    #[test]
    fn header_block_iter_returns_all_live() {
        let mut block = HeaderBlock::empty();
        block.set("x", b"1");
        block.set("y", b"2");
        block.set("z", b"3");

        let names: Vec<&[u8]> = block.iter().map(|(n, _)| n).collect();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&b"x".as_ref()));
        assert!(names.contains(&b"y".as_ref()));
        assert!(names.contains(&b"z".as_ref()));
    }

    #[test]
    fn header_block_len_after_multiple_removes() {
        let mut block = HeaderBlock::empty();
        block.set("a", b"1");
        block.set("b", b"2");
        block.set("c", b"3");
        block.set("d", b"4");
        assert_eq!(block.len(), 4);

        block.remove("a");
        block.remove("c");
        assert_eq!(block.len(), 2);

        block.remove("d");
        assert_eq!(block.len(), 1);
    }

    #[test]
    fn header_block_compact_reclaims_space() {
        let mut block = HeaderBlock::empty();
        block.set("keep", b"yes");
        block.set("remove1", b"xxxxxxxxxxxxxxxxxxxx");
        block.set("remove2", b"yyyyyyyyyyyyyyyyyyyy");
        block.set("also-keep", b"yes");

        block.remove("remove1");
        block.remove("remove2");

        let before = block.data.len();
        block.compact();
        let after = block.data.len();

        assert!(after < before, "compact should shrink data: before={before}, after={after}");
        assert_eq!(block.len(), 2);
        assert_eq!(block.count, 2);

        // Verify data integrity after compaction.
        let map = block.into_header_map();
        assert_eq!(map.get("keep").unwrap(), "yes");
        assert_eq!(map.get("also-keep").unwrap(), "yes");
    }

    #[test]
    fn header_block_from_empty_map() {
        let map = axum::http::HeaderMap::new();
        let block = HeaderBlock::from_header_map(&map);
        assert_eq!(block.len(), 0);
        assert!(block.is_empty());
        let map2 = block.into_header_map();
        assert!(map2.is_empty());
    }

    // ── Regression: multi-valued headers survive the round-trip ──
    //
    // BUG: into_header_map used `map.insert`, which removes all prior values
    // for a name, so every value but the last of a multi-valued header (e.g.
    // Set-Cookie) was silently dropped. Now it uses `map.append`.
    #[test]
    fn header_block_roundtrip_preserves_multivalue_headers() {
        let mut map = axum::http::HeaderMap::new();
        // Two Set-Cookie values under the same name — the classic multi-value case.
        map.append("set-cookie", "a=1".parse().unwrap());
        map.append("set-cookie", "b=2".parse().unwrap());
        assert_eq!(map.get_all("set-cookie").iter().count(), 2);

        let block = HeaderBlock::from_header_map(&map);
        // Both entries are stored distinctly.
        assert_eq!(block.len(), 2);

        let map2 = block.into_header_map();
        // Without the fix this is 1 (only "b=2" survives); with the fix it is 2.
        let values: Vec<_> = map2
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(values.len(), 2, "both Set-Cookie values must survive");
        assert!(values.contains(&"a=1".to_string()));
        assert!(values.contains(&"b=2".to_string()));
    }

    // ── Regression: headers larger than 65535 bytes are not truncated ──
    //
    // BUG: name_len/value_len were stored as u16, so a value >= 65536 bytes
    // had its on-buffer length truncated (e.g. 70000 -> 4464), desynchronising
    // the parse walk and panicking with an out-of-bounds slice. Lengths are
    // now u32 (ENTRY_HEADER_SIZE = 9).
    #[test]
    fn header_block_handles_header_value_over_u16_max() {
        // 70_000 bytes — well past u16::MAX (65_535). Realistic for a big
        // Cookie / JWT bearer token / custom header.
        let big_value = vec![b'x'; 70_000];
        let mut map = axum::http::HeaderMap::new();
        map.insert(
            "authorization",
            axum::http::HeaderValue::from_bytes(&big_value).unwrap(),
        );
        map.insert("x-small", "ok".parse().unwrap());

        let mut block = HeaderBlock::from_header_map(&map);
        assert_eq!(block.len(), 2);

        // Each of these walks the buffer; under the old u16 truncation the
        // desynced length caused an out-of-bounds panic here.
        let removed = block.strip_hop_by_hop();
        assert_eq!(removed, 0); // neither header is hop-by-hop
        assert_eq!(block.iter().count(), 2);

        let map2 = block.into_header_map();
        assert_eq!(map2.get("authorization").unwrap().as_bytes(), &big_value[..]);
        assert_eq!(map2.get("x-small").unwrap(), "ok");
    }

    // ── HopByHopStripper — Direct and Block strategies ──

    #[test]
    fn strip_direct_with_empty_headers() {
        let mut map = axum::http::HeaderMap::new();
        strip_hop_by_hop_direct(&mut map);
        assert!(map.is_empty());
    }

    #[test]
    fn strip_direct_with_no_hop_by_hop_headers() {
        let mut map = axum::http::HeaderMap::new();
        map.insert("content-type", "text/html".parse().unwrap());
        map.insert("x-custom", "value".parse().unwrap());
        map.insert("accept", "application/json".parse().unwrap());

        strip_hop_by_hop_direct(&mut map);
        assert_eq!(map.len(), 3);
        assert_eq!(map.get("content-type").unwrap(), "text/html");
        assert_eq!(map.get("x-custom").unwrap(), "value");
        assert_eq!(map.get("accept").unwrap(), "application/json");
    }

    #[test]
    fn strip_block_with_empty_headers() {
        let mut map = axum::http::HeaderMap::new();
        strip_hop_by_hop_block(&mut map);
        assert!(map.is_empty());
    }

    #[test]
    fn strip_block_with_no_hop_by_hop_headers() {
        let mut map = axum::http::HeaderMap::new();
        map.insert("content-type", "text/html".parse().unwrap());
        map.insert("x-request-id", "123".parse().unwrap());

        strip_hop_by_hop_block(&mut map);
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn header_block_strip_case_insensitive() {
        // HeaderBlock::from_header_map uses HeaderMap which lowercases names,
        // but the is_hop_by_hop_name check should be case-insensitive.
        assert!(super::is_hop_by_hop_name("Connection"));
        assert!(super::is_hop_by_hop_name("CONNECTION"));
        assert!(super::is_hop_by_hop_name("connection"));
        assert!(super::is_hop_by_hop_name("Transfer-Encoding"));
        assert!(!super::is_hop_by_hop_name("content-type"));
    }

    // ── BodyBuf — all three variants ──

    #[test]
    fn body_buf_linear_len_is_empty() {
        BUFFER_STRATEGY.store(BufferStrategy::Standard as u8, Ordering::Relaxed);
        let buf = BodyBuf::acquire(32);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        BUFFER_STRATEGY.store(BufferStrategy::Pooled as u8, Ordering::Relaxed);
    }

    #[test]
    fn body_buf_ring_len_is_empty() {
        BUFFER_STRATEGY.store(BufferStrategy::Ring as u8, Ordering::Relaxed);
        let mut buf = BodyBuf::acquire(32);
        assert!(buf.is_empty());
        buf.write(b"data");
        assert!(!buf.is_empty());
        assert_eq!(buf.len(), 4);
        BUFFER_STRATEGY.store(BufferStrategy::Pooled as u8, Ordering::Relaxed);
    }

    #[test]
    fn body_buf_into_vec_all_variants() {
        for strategy in [BufferStrategy::Standard, BufferStrategy::Pooled, BufferStrategy::Ring] {
            BUFFER_STRATEGY.store(strategy as u8, Ordering::Relaxed);
            let mut buf = BodyBuf::acquire(64);
            buf.write(b"convert me");
            let vec = buf.into_vec();
            assert_eq!(&vec, b"convert me", "failed for strategy {:?}", strategy);
        }
        BUFFER_STRATEGY.store(BufferStrategy::Pooled as u8, Ordering::Relaxed);
    }

    // ── Strategy from_u8 edge cases ──

    #[test]
    fn buffer_strategy_from_u8_unknown_defaults() {
        assert_eq!(BufferStrategy::from_u8(0), BufferStrategy::Standard);
        assert_eq!(BufferStrategy::from_u8(1), BufferStrategy::Pooled);
        assert_eq!(BufferStrategy::from_u8(2), BufferStrategy::Ring);
        assert_eq!(BufferStrategy::from_u8(255), BufferStrategy::Standard); // unknown
        assert_eq!(BufferStrategy::from_u8(99), BufferStrategy::Standard);  // unknown
    }

    #[test]
    fn header_strategy_from_u8_unknown_defaults() {
        assert_eq!(HeaderStrategy::from_u8(0), HeaderStrategy::Standard);
        assert_eq!(HeaderStrategy::from_u8(1), HeaderStrategy::Direct);
        assert_eq!(HeaderStrategy::from_u8(2), HeaderStrategy::Block);
        assert_eq!(HeaderStrategy::from_u8(255), HeaderStrategy::Standard); // unknown
        assert_eq!(HeaderStrategy::from_u8(42), HeaderStrategy::Standard);  // unknown
    }

    // ── buf_xfer: wrap-around transfer ──

    #[test]
    fn xfer_with_wrap_around_src() {
        let mut src = RingBuf::with_exact_capacity(8);
        let mut dst = RingBuf::with_exact_capacity(16);

        // Force wrap in src: write 6, consume 5, write 5 more
        src.write(b"ABCDEF");
        src.consume(5);
        src.write(b"GHIJK");
        // src now has F,G,H,I,J,K with wrap
        assert_eq!(src.len(), 6);
        let (_a, b) = src.read_slices();
        assert!(!b.is_empty(), "src should be wrapped");

        let n = buf_xfer(&mut src, &mut dst);
        assert_eq!(n, 6);
        assert!(src.is_empty());

        let vec = dst.into_vec();
        assert_eq!(&vec, b"FGHIJK");
    }

    #[test]
    fn xfer_full_dst() {
        let mut src = RingBuf::with_exact_capacity(8);
        let mut dst = RingBuf::with_exact_capacity(4);

        src.write(b"ABCDEF");
        dst.write(b"XXXX"); // dst is full

        let n = buf_xfer(&mut src, &mut dst);
        assert_eq!(n, 0);
        assert_eq!(src.len(), 6); // unchanged
    }
}
