# Algorithm & Structure Provenance

Which proxy each ported algorithm/structure originates from.

## Algorithms Crate (`crates/algorithms/`)

### Hashing (`goals/hash/`)

| Module | Origin | Notes |
|--------|--------|-------|
| `djb.rs` | Compat (nginx) | DJB hash, used by nginx hash tables |
| `murmur2.rs` | Compat (nginx) | MurmurHash2 |
| `wt6.rs` | HAProxy | Willy Tarreau's dual-state hash with data-dependent rotation |
| `sdbm.rs` | HAProxy | SDBM hash (`c + (h<<6) + (h<<16) - h`) |
| `crc32c.rs` | HAProxy | CRC32c Castagnoli (RFC 4960), table-based |
| `xxhash.rs` | HAProxy | XXH32 + XXH64, state-of-the-art non-crypto hash |
| `siphash.rs` | ATS | SipHash-2-4 / SipHash-1-3 keyed MAC hash (DoS-resistant, configurable rounds) |
| `snowflake.rs` | ATS | Twitter-style 64-bit Snowflake ID generator (timestamp + machine + sequence) |

### Checksum (`goals/checksum/`)

| Module | Origin | Notes |
|--------|--------|-------|
| `crc32.rs` | Compat (nginx) | CRC32 with 3 variants (Fast, TableLong, NibbleShort) |

### Encoding (`goals/encode/`)

| Module | Origin | Notes |
|--------|--------|-------|
| `base64.rs` | Compat (nginx) | Base64 + Base64URL encode/decode |
| `hex.rs` | Compat (nginx) | Hex dump, hex-to-int |
| `escape_uri.rs` | Compat (nginx) | URI escape with LUT counting |
| `unescape_uri.rs` | Compat (nginx) | URI unescape |
| `escape_html.rs` | Compat (nginx) | HTML entity escaping |
| `escape_json.rs` | Compat (nginx) | JSON string escaping |
| `slz.rs` | HAProxy | Stateless DEFLATE/GZIP/ZLIB (static Huffman, no window) |
| `uri_normalize.rs` | HAProxy | RFC 3986 URI normalization (dot resolve, slash merge, query sort) |
| `accept_encoding.rs` | Traefik | RFC 9110 Accept-Encoding weighted negotiation (q-values, wildcard, identity) |
| `etag_encode.rs` | Caddy | ETag modification for encoded responses (RFC 9110 §8.8.3, suffix append/strip) |
| `path_trim.rs` | Caddy | Escape-aware path prefix/suffix trimming (encoding bypass prevention) |
| `golomb_set.rs` | H2O | Golomb-Rice coded sets (compact sorted integer encoding/decoding) |
| `vary_encode.rs` | Varnish | Compact binary Vary key encoding (order-independent, BTreeMap-sorted) |

### HTTP Codec (`goals/http_codec/`)

| Module | Origin | Notes |
|--------|--------|-------|
| `chunked.rs` | Compat (nginx) | Chunked transfer-encoding parser |
| `http_v2.rs` | Compat (nginx) | HTTP/2 frame header parser |
| `h3_varint.rs` | Compat (nginx) | HTTP/3 QUIC varint + prefix integer |
| `huff_decode.rs` | Compat (nginx) | HPACK Huffman decoder |
| `huff_encode.rs` | Compat (nginx) | HPACK Huffman encoder |
| `ws_mask.rs` | Caddy | WebSocket close frame + word-aligned XOR masking (RFC 6455) |
| `vary_key.rs` | Pingora | Order-independent HTTP Vary key builder (BTreeMap + deterministic hash) |
| `replay_body.rs` | linkerd2-proxy | Retryable request body buffer (lazy capture, capped, replay on retry) |
| `ttl_calc.rs` | Varnish | RFC 7234 cache TTL/grace/keep calculator (clock-skew tolerant, conditional 304) |
| `h2_scheduler.rs` | H2O | HTTP/2 dependency-tree weighted fair queue (deficit-based WRR scheduling) |
| `ext_priority.rs` | H2O | RFC 9218 Extensible Priorities (urgency/incremental parsing, H2 weight conversion) |
| `range_slicer.rs` | ATS | Content-Range block decomposition for cache slicing (multi-range, block alignment) |

### Networking (`goals/inet/`)

| Module | Origin | Notes |
|--------|--------|-------|
| `ipv4.rs` | Compat (nginx) | IPv4/IPv6 address parsing |
| `cidr.rs` | Compat (nginx) | CIDR matching for IPv4/IPv6 |
| `ntop.rs` | Compat (nginx) | Address-to-string conversion |
| `proxy_protocol.rs` | Compat (nginx) | PROXY protocol v1/v2 parsing |
| `sni_check.rs` | Traefik | Domain fronting protection (Host vs TLS.ServerName mismatch → 421) |
| `cname_flatten.rs` | Traefik | Recursive CNAME chain resolution with TTL-aware caching |
| `domain_dedup.rs` | Traefik | ACME domain deduplication (wildcard coverage, multi-label matching) |
| `cert_selection.rs` | Caddy | Multi-criteria certificate selection (serial, org, key algo, tags) |
| `sni_index.rs` | Caddy | SNI-indexed policy fast path (O(1) lookup for >30 policies) |

### Parsing (`goals/parse/`)

| Module | Origin | Notes |
|--------|--------|-------|
| `decimal.rs` | Compat (nginx) | Numeric parsers |
| `conf_scan.rs` | Compat (nginx) | Configuration token scanner |
| `http_time.rs` | Compat (nginx) | HTTP date/time parser |
| `integers.rs` | Compat (nginx) | atoi, atofp, atosz, hextoi |
| `offset.rs` | Compat (nginx) | Size parsing with k/m/g suffixes |

### String Operations (`goals/string/`)

| Module | Origin | Notes |
|--------|--------|-------|
| `compare.rs` | Compat (nginx) | Case-insensitive compare, DNS compare, filename compare |
| `misc.rs` | Compat (nginx) | strlow, strnlen, strlchr, cpystrn |
| `search.rs` | Compat (nginx) | Substring search (strstrn, strcasestrn) |
| `sort.rs` | Compat (nginx) | Stable insertion sort |

### Rate Limiting (`goals/rate_limit/`)

| Module | Origin | Notes |
|--------|--------|-------|
| `leaky_bucket.rs` | Compat (nginx) | Leaky bucket algorithm |
| `freq_ctr.rs` | HAProxy | Lock-free 2-bucket sliding-window frequency counter with CAS rotation |
| `atomic_token_bucket.rs` | Envoy | Lock-free CAS token bucket (Folly-inspired, time-as-tokens representation) |
| `gradient_controller.rs` | Envoy | Adaptive concurrency limiter (latency gradient + sqrt burst headroom) |
| `admission_control.rs` | Envoy | Probabilistic request rejection (rolling success rate, aggression exponent) |
| `ip_reputation.rs` | ATS | Multi-tier sieve-LRU IP reputation tracker (adaptive bucket promotion, aging) |
| `histogram.rs` | ATS | Stepped logarithmic histogram (O(1) insert, configurable range/span bits, decay) |
| `dagor.rs` | Paper (DAGOR) | Compound priority admission control (business+user, histogram-adaptive shedding, WeChat SoCC'18) |
| `codel.rs` | Paper (RFC 8289) | CoDel active queue management (min sojourn time, sqrt-paced dropping) |

### Upstream Pick / Load Balancing (`goals/upstream_pick/`)

| Module | Origin | Notes |
|--------|--------|-------|
| `ip_hash.rs` | Compat (nginx) | IP-hash upstream selection |
| `split_clients.rs` | Compat (nginx) | Split-clients distribution |
| `fwlc.rs` | HAProxy | Fast Weighted Least Connections (BTreeMap-keyed by weighted load) |
| `fwrr.rs` | HAProxy | Fast Weighted Round Robin (3-tree with fractional remainder) |
| `fas.rs` | HAProxy | First Available Server bin-packing (Gandhi et al.) |
| `chash_bounded.rs` | HAProxy | Consistent Hash with Bounded Loads (Mirrokni/Thorup/Zadimoghaddam 2016) |
| `maglev.rs` | Envoy | Maglev consistent hashing (Google, O(1) lookup, prime-sized table) |
| `edf.rs` | Envoy | Earliest Deadline First scheduler (min-heap weighted round robin) |
| `wrsq.rs` | Envoy | Weighted Random Selection Queue (weight-grouped FIFO scheduling) |
| `slow_start.rs` | Envoy | Slow start weight ramp (configurable aggression, min weight floor) |
| `locality_lb.rs` | Envoy | Locality-weighted load balancing (zone-aware, overprovisioning factor) |
| `priority_lb.rs` | Envoy | Priority-based load distribution (multi-level failover, panic mode) |
| `peak_ewma.rs` | linkerd2-proxy | Peak EWMA latency-based load balancing (snap-up, smooth decay) |
| `completion_tracker.rs` | linkerd2-proxy | Load completion signaling (first-byte, headers, full response) |
| `p2c.rs` | Paper (Mitzenmacher) | Power of Two Choices (sample 2, pick lower load, O(log log n) max) |

### Crypto (`goals/crypt/`)

| Module | Origin | Notes |
|--------|--------|-------|
| `apr1.rs` | Compat (nginx) | Apache APR1 password hash |
| `plain.rs` | Compat (nginx) | Plaintext password check |
| `sha.rs` | Compat (nginx) | SHA / SSHA password hash |

### Text (`goals/text/`)

| Module | Origin | Notes |
|--------|--------|-------|
| `utf8.rs` | Compat (nginx) | UTF-8 decode/validate, utf8_length, utf8_cpystrn |

### Tree Algorithms (`goals/tree/`)

| Module | Origin | Notes |
|--------|--------|-------|
| `radix_lpm.rs` | Compat (nginx) | Radix tree longest-prefix match (32-bit + 128-bit) |
| `rbtree.rs` | Compat (nginx) | Red-black tree |
| `keyed_rbtree.rs` | Compat (nginx) | Keyed red-black tree |
| `str_rbtree.rs` | Compat (nginx) | String-keyed red-black tree |
| `rbtree_timer.rs` | Compat (nginx) | Timer-optimized rbtree |

### Congestion Control (`goals/congestion/`)

| Module | Origin | Notes |
|--------|--------|-------|
| `cubic.rs` | HAProxy | RFC 9438 CUBIC (integer math, HyStart++, TCP-friendly region) |
| `bbr.rs` | HAProxy | BBRv3 (model-based, MaxBw + RTprop, 4-phase, pacing) |

### Resilience (`goals/resilience/`)

| Module | Origin | Notes |
|--------|--------|-------|
| `circuit_breaker.rs` | Traefik | 3-state circuit breaker (Closed→Open→HalfOpen), error ratio + threshold tripping |
| `backoff.rs` | Traefik | Bounded exponential backoff (`2^(1/(n-1))` multiplier, ~2× total bound) |
| `passive_health.rs` | Traefik | Sliding-window passive health checker with auto-recovery |
| `cert_renewal.rs` | Traefik | Adaptive certificate renewal scheduling (6 tiers by cert lifetime) |
| `distributed_stek.rs` | Caddy | Distributed STEK coordination (cluster key rotation via storage) |
| `retry.rs` | Caddy | Idempotency-aware retry logic (dial vs connection error distinction) |
| `active_health.rs` | Caddy | Active health check with hysteresis (consecutive pass/fail thresholds) |
| `outlier_detection.rs` | Envoy | Statistical outlier detection (mean/stdev success rate ejection, exponential backoff) |
| `success_rate.rs` | Envoy | Double-buffered lock-free success rate accumulator |
| `retry_budget.rs` | Envoy | Dynamic retry budget (% of active requests, min concurrency floor) |
| `jittered_backoff.rs` | Envoy | AWS-style fully-jittered exponential backoff |
| `stampede_lock.rs` | Pingora | Cache thundering-herd prevention (write permit + reader wait, age timeout) |
| `cache_predictor.rs` | Pingora | Cacheability predictor (LRU of known-uncacheable URL hashes) |
| `failfast.rs` | linkerd2-proxy | Readiness-based circuit breaker (Open/Waiting/FailFast + tri-state gate) |
| `cache_promote.rs` | ATS | Hit/byte threshold admission control (LRU tracker, freelist recycling, chance policy) |

### Protocol Codecs

| Module | Origin | Notes |
|--------|--------|-------|
| `goals/fix/` | HAProxy | FIX protocol parser (tag-value, checksum, version-aware) |
| `goals/mqtt/` | HAProxy | MQTT v3.1/3.1.1/5.0 parser (CONNECT, variable-length int) |
| `goals/jwt/` | HAProxy | JWT tokenize, JWS HMAC-SHA verify, JWE types |
| `goals/pattern/matcher.rs` | HAProxy | 14-type pattern matcher (prefix/suffix/domain/IP/regex) |
| `goals/pattern/matcher_tree.rs` | Traefik | Binary matcher tree (compound boolean rule eval, short-circuit) |
| `goals/pattern/ban_evaluator.rs` | Varnish | Predicate-based cache invalidation (conjunction of field/operator/value tests) |
| `goals/fingerprint/` | HAProxy | TCP/IP passive OS fingerprinting |
| `goals/fingerprint/ja4.rs` | ATS | JA4 TLS fingerprint (ClientHello cipher/extension/ALPN hashing, GREASE filtering) |

---

## Structures Crate (`crates/lynxx_structures/`)

| Module | Origin | Notes |
|--------|--------|-------|
| `array.rs` | Compat (nginx) | Dynamic array |
| `buf.rs` | Compat (nginx) | Buffer and buffer chain |
| `dns.rs` | Compat (nginx) | DNS result cache with rotation |
| `drain.rs` | Compat (nginx) | Connection drain pool |
| `file_cache.rs` | Compat (nginx) | LRU open file descriptor cache |
| `hash/` | Compat (nginx) | Hash table with wildcard matching |
| `inet.rs` | Compat (nginx) | IP address wrappers |
| `limit/` | Compat (nginx) | Rate limit zones (req + conn) |
| `list.rs` | Compat (nginx) | Linked list |
| `log.rs` | Compat (nginx) | Log structures |
| `md5.rs` | Compat (nginx) | MD5 context |
| `output_chain.rs` | Compat (nginx) | directio alignment, sendfile splitting, buffer recycler |
| `parse.rs` | Compat (nginx) | Integer/size/time parsers |
| `pool.rs` | Compat (nginx) | Memory pool allocator |
| `queue.rs` | Compat (nginx) | FIFO queue |
| `sha1.rs` | Compat (nginx) | SHA-1 context |
| `shmtx.rs` | Compat (nginx) | Shared memory mutex |
| `slab.rs` | Compat (nginx) | 3-tier bitmap slab allocator |
| `string.rs` | Compat (nginx) | Custom string type |
| `sync/spinlock.rs` | Compat (nginx) | User-space spinlock with backoff |
| `sync/rwlock.rs` | Compat (nginx) | Reader-writer lock with backoff |
| `times.rs` | Compat (nginx) | Millisecond timer |
| `tree/` | Compat (nginx) | Radix trees, red-black trees |
| `ebtree/` | HAProxy | Elastic Binary Trees (eb32, eb64, ebmb, ebst) |
| `stick_table.rs` | HAProxy | 64-shard stick table with freq counters + expiry |
| `ncbuf.rs` | HAProxy | Non-contiguous buffers (gap-encoded + bitmap) for QUIC |
| `lru.rs` | HAProxy | Generic LRU cache with domain/revision model |
| `ring.rs` | HAProxy | Single-producer multi-reader circular buffer |
| `dict.rs` | HAProxy | Thread-safe string interning |
| `dynbuf.rs` | HAProxy | Criticality-aware buffer pool (7 levels, 4 queues) |
| `priority_queue.rs` | HAProxy | Class+time composite-key priority queue |
| `usage_pool.rs` | Caddy | Reference-counted thread-safe object pool (lazy create, auto-destroy) |
| `bit_array.rs` | Envoy | Packed fixed-width element array (1-32 bits per entry, unaligned 64-bit access) |
| `s3fifo.rs` | Pingora | S3-FIFO + TinyLFU cache eviction (small/main queues, Count-Min Sketch admission) |
| `vm_heap.rs` | Varnish | VM-page-aware binary heap (locality-optimized parent/child navigation) |
| `timer_wheel.rs` | H2O | Hierarchical timer wheel (multi-level, O(1) insert/cancel, cascading) |
| `clfus_cache.rs` | ATS | CLFUS RAM cache (frequency-weighted-by-size, ghost history, seen filter, admission gating) |
| `bravo_lock.rs` | ATS | BRAVO reader-biased RWLock (per-slot atomics, zero-contention read fast path) |
| `clock_cache.rs` | ATS | Clock eviction cache (second-chance circular buffer, referenced bit) |
| `write_buffer.rs` | ATS | Aggregate write buffer (aligned write coalescing, reserve + read-back) |
| `arc_cache.rs` | Paper (ARC) | Adaptive Replacement Cache (self-tuning recency/frequency, ghost lists, FAST'03) |
| `wtinylfu.rs` | Paper (W-TinyLFU) | Window TinyLFU (4-bit Count-Min Sketch, SLRU main, Einziger 2015) |

---

## Summary

| Origin | Algorithms | Structures | Total |
|--------|-----------|------------|-------|
| Compat (nginx) | ~30 modules | ~23 modules | ~53 |
| HAProxy | ~15 modules | ~8 modules | ~23 |
| Traefik | 9 modules | — | 9 |
| Caddy | 8 modules | 1 module | 9 |
| Envoy | 13 modules | 1 module | 14 |
| Pingora | 3 modules | 1 module | 4 |
| linkerd2-proxy | 4 modules | — | 4 |
| Varnish | 3 modules | 1 module | 4 |
| H2O | 3 modules | 1 module | 4 |
| ATS | 7 modules | 4 modules | 11 |
| Papers | 3 modules | 2 modules | 5 |
| **Total** | **~98** | **~42** | **~140** |
