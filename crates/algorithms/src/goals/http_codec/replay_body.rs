/// Retryable body replay buffer (inspired by linkerd2-proxy).
///
/// When a proxy needs to retry a request, the original body may already have
/// been partially or fully consumed.  `ReplayBody` captures up to `capacity`
/// bytes so the body can be replayed on a subsequent attempt.  If the body
/// exceeds the capacity the buffer is marked full and replay is no longer
/// possible.

pub struct ReplayBody {
    buf: Vec<u8>,
    capacity: usize,
    full: bool,
}

impl ReplayBody {
    /// Create a new replay buffer that stores at most `capacity` bytes.
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity.min(8192)),
            capacity,
            full: false,
        }
    }

    /// Append a chunk to the buffer.  Returns `true` if the chunk fit entirely,
    /// `false` if the buffer has overflowed (further pushes are ignored).
    pub fn push(&mut self, chunk: &[u8]) -> bool {
        if self.full {
            return false;
        }
        if self.buf.len() + chunk.len() > self.capacity {
            self.full = true;
            return false;
        }
        self.buf.extend_from_slice(chunk);
        true
    }

    /// Return the buffered bytes for replay.
    pub fn replay(&self) -> &[u8] {
        &self.buf
    }

    /// Reset the buffer for a fresh capture pass.
    pub fn reset(&mut self) {
        self.buf.clear();
        self.full = false;
    }

    /// Number of bytes currently buffered.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the capacity was exceeded.
    pub fn is_full(&self) -> bool {
        self.full
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_push_and_replay() {
        let mut rb = ReplayBody::new(1024);
        assert!(rb.push(b"hello "));
        assert!(rb.push(b"world"));
        assert_eq!(rb.replay(), b"hello world");
        assert_eq!(rb.len(), 11);
        assert!(!rb.is_full());
    }

    #[test]
    fn test_overflow() {
        let mut rb = ReplayBody::new(8);
        assert!(rb.push(b"1234"));
        assert!(!rb.push(b"56789")); // 4 + 5 > 8
        assert!(rb.is_full());
        // Further pushes are ignored
        assert!(!rb.push(b"a"));
    }

    #[test]
    fn test_exact_capacity() {
        let mut rb = ReplayBody::new(4);
        assert!(rb.push(b"ab"));
        assert!(rb.push(b"cd"));
        assert_eq!(rb.len(), 4);
        assert!(!rb.is_full());
    }

    #[test]
    fn test_reset() {
        let mut rb = ReplayBody::new(8);
        rb.push(b"data");
        rb.reset();
        assert_eq!(rb.len(), 0);
        assert!(!rb.is_full());
        assert!(rb.push(b"newdata!"));
        assert_eq!(rb.replay(), b"newdata!");
    }

    #[test]
    fn test_empty() {
        let rb = ReplayBody::new(100);
        assert_eq!(rb.len(), 0);
        assert!(!rb.is_full());
        assert!(rb.replay().is_empty());
    }

    #[test]
    fn test_zero_capacity() {
        let mut rb = ReplayBody::new(0);
        assert!(!rb.push(b"a"));
        assert!(rb.is_full());
    }
}
