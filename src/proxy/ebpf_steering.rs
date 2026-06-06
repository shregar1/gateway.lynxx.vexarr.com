//! eBPF/XDP packet steering — kernel-bypass fast-path for routing decisions.
//!
//! On Linux 5.15+ with eBPF support, Lynxx can offload packet-level routing
//! decisions to XDP programs attached to the NIC, achieving wire-speed
//! forwarding without context switches.
//!
//! This module provides:
//! - **XDP program descriptors**: metadata for compiled eBPF programs
//! - **Map descriptors**: shared eBPF maps for userspace ↔ kernel communication
//! - **Steering rules**: CPU/queue affinity, backend selection maps
//! - **Feature detection**: probe kernel capabilities at startup
//! - **Statistics**: per-program packet/byte/drop counters
//!
//! # Architecture
//!
//! ```text
//! NIC → XDP program → steering map lookup → redirect to backend / pass to stack
//!                        ↑
//!                  userspace updater (Lynxx control plane)
//! ```
//!
//! The userspace control plane updates eBPF maps with current backend lists,
//! health status, and routing rules. The XDP program executes in the kernel's
//! fast path and makes per-packet decisions without crossing the kernel/user
//! boundary.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::time::{Duration, Instant};

// ═══════════════════════════════════════════════════════════════════════════
// Global toggles
// ═══════════════════════════════════════════════════════════════════════════

static EBPF_ENABLED: AtomicBool = AtomicBool::new(false);
static XDP_MODE: AtomicU8 = AtomicU8::new(0); // 0 = Generic, 1 = Native, 2 = Offload

pub fn is_ebpf_enabled() -> bool {
    EBPF_ENABLED.load(Ordering::Relaxed)
}

pub fn set_ebpf_enabled(v: bool) {
    EBPF_ENABLED.store(v, Ordering::Relaxed);
}

pub fn get_xdp_mode() -> XdpMode {
    XdpMode::from_u8(XDP_MODE.load(Ordering::Relaxed))
}

pub fn set_xdp_mode(mode: XdpMode) {
    XDP_MODE.store(mode as u8, Ordering::Relaxed);
}

// ═══════════════════════════════════════════════════════════════════════════
// XDP attach modes
// ═══════════════════════════════════════════════════════════════════════════

/// How the XDP program is attached to the NIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum XdpMode {
    /// SKB-based generic mode — works everywhere, slowest.
    Generic = 0,
    /// Driver-level native mode — requires driver support, fast.
    Native = 1,
    /// NIC hardware offload — requires SmartNIC, fastest.
    Offload = 2,
}

impl XdpMode {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Native,
            2 => Self::Offload,
            _ => Self::Generic,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::Native => "native",
            Self::Offload => "offload",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// XDP actions (return codes from eBPF programs)
// ═══════════════════════════════════════════════════════════════════════════

/// Standard XDP return codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum XdpAction {
    /// Drop the packet.
    Drop = 1,
    /// Pass to the normal network stack.
    Pass = 2,
    /// Bounce back out the same NIC (hairpin).
    Tx = 3,
    /// Redirect to another NIC or CPU.
    Redirect = 4,
    /// Like Pass, but skip some processing.
    Aborted = 0,
}

impl XdpAction {
    pub fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::Drop,
            2 => Self::Pass,
            3 => Self::Tx,
            4 => Self::Redirect,
            _ => Self::Aborted,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Drop => "XDP_DROP",
            Self::Pass => "XDP_PASS",
            Self::Tx => "XDP_TX",
            Self::Redirect => "XDP_REDIRECT",
            Self::Aborted => "XDP_ABORTED",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// eBPF map types
// ═══════════════════════════════════════════════════════════════════════════

/// Types of eBPF maps used for steering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MapType {
    /// Hash map for exact-match lookups (IP → backend).
    Hash = 0,
    /// Array map for indexed access (CPU affinity).
    Array = 1,
    /// LRU hash for bounded caches (connection tracking).
    LruHash = 2,
    /// Per-CPU array for lock-free per-core counters.
    PerCpuArray = 3,
    /// Ring buffer for event streaming to userspace.
    RingBuf = 4,
    /// Device map for XDP_REDIRECT targets.
    DevMap = 5,
    /// CPU map for XDP_REDIRECT to specific CPUs.
    CpuMap = 6,
}

impl MapType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Array,
            2 => Self::LruHash,
            3 => Self::PerCpuArray,
            4 => Self::RingBuf,
            5 => Self::DevMap,
            6 => Self::CpuMap,
            _ => Self::Hash,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Hash => "BPF_MAP_TYPE_HASH",
            Self::Array => "BPF_MAP_TYPE_ARRAY",
            Self::LruHash => "BPF_MAP_TYPE_LRU_HASH",
            Self::PerCpuArray => "BPF_MAP_TYPE_PERCPU_ARRAY",
            Self::RingBuf => "BPF_MAP_TYPE_RINGBUF",
            Self::DevMap => "BPF_MAP_TYPE_DEVMAP",
            Self::CpuMap => "BPF_MAP_TYPE_CPUMAP",
        }
    }

    /// Whether this map type supports per-CPU semantics.
    pub fn is_per_cpu(&self) -> bool {
        matches!(self, Self::PerCpuArray | Self::CpuMap)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Map descriptor
// ═══════════════════════════════════════════════════════════════════════════

/// Describes a single eBPF map.
#[derive(Debug, Clone)]
pub struct MapDescriptor {
    /// Map name (as referenced in the eBPF program).
    pub name: String,
    /// Map type.
    pub map_type: MapType,
    /// Key size in bytes.
    pub key_size: u32,
    /// Value size in bytes.
    pub value_size: u32,
    /// Maximum entries.
    pub max_entries: u32,
    /// Map flags (e.g. BPF_F_NO_PREALLOC).
    pub flags: u32,
}

impl MapDescriptor {
    pub fn new(name: &str, map_type: MapType, key_size: u32, value_size: u32, max_entries: u32) -> Self {
        Self {
            name: name.to_string(),
            map_type,
            key_size,
            value_size,
            max_entries,
            flags: 0,
        }
    }

    pub fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Total memory footprint estimate in bytes.
    pub fn estimated_memory(&self) -> u64 {
        // Widen before adding/multiplying: `key_size + value_size` is a u32 add
        // that can wrap before the cast, and the product can exceed u64 for an
        // absurd config. Saturate instead of wrapping silently in release.
        let entry_size = self.key_size as u64 + self.value_size as u64;
        entry_size.saturating_mul(self.max_entries as u64)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Program descriptor
// ═══════════════════════════════════════════════════════════════════════════

/// Describes a compiled eBPF/XDP program ready for loading.
#[derive(Debug, Clone)]
pub struct ProgramDescriptor {
    /// Human-readable program name.
    pub name: String,
    /// Path to the compiled .o ELF file.
    pub object_path: String,
    /// Section name in the ELF (e.g., "xdp", "xdp/ingress").
    pub section: String,
    /// Expected XDP attach mode.
    pub attach_mode: XdpMode,
    /// Maps this program uses.
    pub maps: Vec<MapDescriptor>,
    /// License string (must match kernel expectations, e.g. "GPL").
    pub license: String,
    /// Minimum kernel version required.
    pub min_kernel: KernelVersion,
}

impl ProgramDescriptor {
    pub fn new(name: &str, object_path: &str, section: &str) -> Self {
        Self {
            name: name.to_string(),
            object_path: object_path.to_string(),
            section: section.to_string(),
            attach_mode: XdpMode::Generic,
            maps: Vec::new(),
            license: "GPL".to_string(),
            min_kernel: KernelVersion::new(5, 15, 0),
        }
    }

    pub fn with_mode(mut self, mode: XdpMode) -> Self {
        self.attach_mode = mode;
        self
    }

    pub fn with_map(mut self, map: MapDescriptor) -> Self {
        self.maps.push(map);
        self
    }

    pub fn with_license(mut self, license: &str) -> Self {
        self.license = license.to_string();
        self
    }

    pub fn with_min_kernel(mut self, major: u16, minor: u16, patch: u16) -> Self {
        self.min_kernel = KernelVersion::new(major, minor, patch);
        self
    }

    /// Total estimated memory for all maps.
    pub fn total_map_memory(&self) -> u64 {
        self.maps.iter().map(|m| m.estimated_memory()).sum()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Kernel version
// ═══════════════════════════════════════════════════════════════════════════

/// A parsed kernel version for feature gating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KernelVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl KernelVersion {
    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self { major, minor, patch }
    }

    /// Parse from "5.15.0-generic" or "6.1.0" style strings.
    pub fn parse(s: &str) -> Option<Self> {
        let version_part = s.split('-').next()?;
        let mut parts = version_part.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        Some(Self { major, minor, patch })
    }

    /// Check if this version supports a required minimum.
    pub fn supports(&self, required: &KernelVersion) -> bool {
        self >= required
    }
}

impl std::fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Steering rule
// ═══════════════════════════════════════════════════════════════════════════

/// A packet steering rule that maps traffic to a destination.
#[derive(Debug, Clone)]
pub struct SteeringRule {
    /// Rule ID for deduplication.
    pub id: u32,
    /// Priority (lower = higher priority).
    pub priority: u16,
    /// Match criteria.
    pub match_spec: MatchSpec,
    /// Action to take.
    pub action: SteeringAction,
    /// Whether this rule is active.
    pub enabled: bool,
}

impl SteeringRule {
    pub fn new(id: u32, priority: u16, match_spec: MatchSpec, action: SteeringAction) -> Self {
        Self {
            id,
            priority,
            match_spec,
            action,
            enabled: true,
        }
    }

    pub fn disable(&mut self) {
        self.enabled = false;
    }

    pub fn enable(&mut self) {
        self.enabled = true;
    }
}

/// What to match in the packet.
#[derive(Debug, Clone)]
pub struct MatchSpec {
    /// Source IP prefix (CIDR notation string, e.g. "10.0.0.0/8").
    pub src_prefix: Option<String>,
    /// Destination port.
    pub dst_port: Option<u16>,
    /// IP protocol (6 = TCP, 17 = UDP).
    pub protocol: Option<u8>,
    /// VLAN ID.
    pub vlan_id: Option<u16>,
}

impl MatchSpec {
    pub fn any() -> Self {
        Self {
            src_prefix: None,
            dst_port: None,
            protocol: None,
            vlan_id: None,
        }
    }

    pub fn tcp_port(port: u16) -> Self {
        Self {
            src_prefix: None,
            dst_port: Some(port),
            protocol: Some(6),
            vlan_id: None,
        }
    }

    pub fn udp_port(port: u16) -> Self {
        Self {
            src_prefix: None,
            dst_port: Some(port),
            protocol: Some(17),
            vlan_id: None,
        }
    }

    pub fn from_prefix(prefix: &str) -> Self {
        Self {
            src_prefix: Some(prefix.to_string()),
            dst_port: None,
            protocol: None,
            vlan_id: None,
        }
    }

    /// Number of fields that participate in the match.
    pub fn specificity(&self) -> u8 {
        let mut s = 0u8;
        if self.src_prefix.is_some() {
            s += 1;
        }
        if self.dst_port.is_some() {
            s += 1;
        }
        if self.protocol.is_some() {
            s += 1;
        }
        if self.vlan_id.is_some() {
            s += 1;
        }
        s
    }
}

/// What to do with matched packets.
#[derive(Debug, Clone)]
pub enum SteeringAction {
    /// Forward to a specific CPU core.
    ToCpu(u32),
    /// Forward to a specific NIC queue.
    ToQueue(u32),
    /// Redirect to a specific network interface (ifindex).
    RedirectIf(u32),
    /// Drop the packet.
    Drop,
    /// Pass to normal network stack.
    Pass,
}

impl SteeringAction {
    pub fn label(&self) -> &'static str {
        match self {
            Self::ToCpu(_) => "to_cpu",
            Self::ToQueue(_) => "to_queue",
            Self::RedirectIf(_) => "redirect_if",
            Self::Drop => "drop",
            Self::Pass => "pass",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Steering table
// ═══════════════════════════════════════════════════════════════════════════

/// A collection of steering rules, sorted by priority.
pub struct SteeringTable {
    rules: Vec<SteeringRule>,
    /// Maximum rules allowed.
    max_rules: usize,
}

impl SteeringTable {
    pub fn new(max_rules: usize) -> Self {
        Self {
            rules: Vec::new(),
            max_rules: max_rules.max(8),
        }
    }

    /// Insert a rule, maintaining priority order. Returns false if at capacity.
    pub fn insert(&mut self, rule: SteeringRule) -> bool {
        // BUG FIX: dedup BEFORE the capacity check. Previously the capacity
        // guard ran first, so updating an existing rule (same id) while the
        // table was full was rejected and the live update silently dropped,
        // even though the retain would have freed its slot. Removing the old
        // entry first means an update never trips the capacity limit; only a
        // genuinely new id can be rejected when full.
        self.rules.retain(|r| r.id != rule.id);
        if self.rules.len() >= self.max_rules {
            return false;
        }
        let pos = self
            .rules
            .binary_search_by_key(&rule.priority, |r| r.priority)
            .unwrap_or_else(|e| e);
        self.rules.insert(pos, rule);
        true
    }

    /// Remove a rule by ID.
    pub fn remove(&mut self, id: u32) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != id);
        self.rules.len() < before
    }

    /// Find the first matching enabled rule.
    pub fn lookup(&self, src_ip: Option<&str>, dst_port: Option<u16>, protocol: Option<u8>) -> Option<&SteeringRule> {
        self.rules.iter().find(|r| {
            if !r.enabled {
                return false;
            }
            let spec = &r.match_spec;
            if let Some(ref prefix) = spec.src_prefix {
                if let Some(src) = src_ip {
                    if !Self::cidr_contains(prefix, src) {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            if let Some(p) = spec.dst_port {
                if dst_port != Some(p) {
                    return false;
                }
            }
            if let Some(proto) = spec.protocol {
                if protocol != Some(proto) {
                    return false;
                }
            }
            true
        })
    }

    /// CIDR match — proper bitwise prefix comparison honoring the /N mask.
    ///
    /// BUG FIX: the previous implementation broke out of the octet loop on the
    /// first "0" octet of the network and discarded the /N suffix entirely. That
    /// produced both false positives (e.g. "10.0.0.0/24" matched "10.0.99.5"
    /// because it stopped at the third "0" octet) and false negatives (e.g.
    /// "10.20.30.0/16" failed "10.20.99.5" by comparing octets past the mask).
    /// We now parse both sides to u32 and compare under the prefix mask.
    fn cidr_contains(prefix: &str, ip: &str) -> bool {
        let mut split = prefix.split('/');
        let Some(network) = split.next() else {
            return false;
        };
        // Default to a full /32 (host match) when no length is given.
        let len: u32 = match split.next() {
            Some(l) => match l.parse::<u32>() {
                Ok(n) if n <= 32 => n,
                _ => return false,
            },
            None => 32,
        };
        let (Some(net_u32), Some(ip_u32)) =
            (Self::parse_ipv4(network), Self::parse_ipv4(ip))
        else {
            return false;
        };
        // `<< 32` is UB in Rust (shift overflow); handle the /0 case explicitly.
        let mask: u32 = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        (ip_u32 & mask) == (net_u32 & mask)
    }

    /// Parse a dotted-quad IPv4 string into a u32. Returns None if malformed.
    fn parse_ipv4(s: &str) -> Option<u32> {
        let mut octets = [0u8; 4];
        let mut count = 0usize;
        for part in s.split('.') {
            if count >= 4 {
                return None;
            }
            octets[count] = part.parse::<u8>().ok()?;
            count += 1;
        }
        if count != 4 {
            return None;
        }
        Some(u32::from_be_bytes(octets))
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Get all active rules.
    pub fn active_rules(&self) -> Vec<&SteeringRule> {
        self.rules.iter().filter(|r| r.enabled).collect()
    }

    /// Get all rules (including disabled).
    pub fn all_rules(&self) -> &[SteeringRule] {
        &self.rules
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Program statistics
// ═══════════════════════════════════════════════════════════════════════════

/// Per-program packet statistics.
pub struct ProgramStats {
    pub packets_processed: AtomicU64,
    pub bytes_processed: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub packets_redirected: AtomicU64,
    pub packets_passed: AtomicU64,
    pub errors: AtomicU64,
}

impl ProgramStats {
    pub fn new() -> Self {
        Self {
            packets_processed: AtomicU64::new(0),
            bytes_processed: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            packets_redirected: AtomicU64::new(0),
            packets_passed: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }

    pub fn record_packet(&self, bytes: u64, action: XdpAction) {
        self.packets_processed.fetch_add(1, Ordering::Relaxed);
        self.bytes_processed.fetch_add(bytes, Ordering::Relaxed);
        match action {
            XdpAction::Drop => {
                self.packets_dropped.fetch_add(1, Ordering::Relaxed);
            }
            XdpAction::Redirect => {
                self.packets_redirected.fetch_add(1, Ordering::Relaxed);
            }
            XdpAction::Pass => {
                self.packets_passed.fetch_add(1, Ordering::Relaxed);
            }
            XdpAction::Aborted => {
                self.errors.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            packets_processed: self.packets_processed.load(Ordering::Relaxed),
            bytes_processed: self.bytes_processed.load(Ordering::Relaxed),
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
            packets_redirected: self.packets_redirected.load(Ordering::Relaxed),
            packets_passed: self.packets_passed.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

/// Point-in-time snapshot for reporting.
#[derive(Debug, Clone)]
pub struct StatsSnapshot {
    pub packets_processed: u64,
    pub bytes_processed: u64,
    pub packets_dropped: u64,
    pub packets_redirected: u64,
    pub packets_passed: u64,
    pub errors: u64,
}

impl StatsSnapshot {
    /// Drop rate as a fraction 0.0 – 1.0.
    pub fn drop_rate(&self) -> f64 {
        if self.packets_processed == 0 {
            return 0.0;
        }
        self.packets_dropped as f64 / self.packets_processed as f64
    }

    /// Redirect rate as a fraction.
    pub fn redirect_rate(&self) -> f64 {
        if self.packets_processed == 0 {
            return 0.0;
        }
        self.packets_redirected as f64 / self.packets_processed as f64
    }

    /// Average packet size.
    pub fn avg_packet_size(&self) -> f64 {
        if self.packets_processed == 0 {
            return 0.0;
        }
        self.bytes_processed as f64 / self.packets_processed as f64
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CPU affinity map
// ═══════════════════════════════════════════════════════════════════════════

/// Manages CPU ↔ RX-queue affinity for RSS/XDP_REDIRECT.
pub struct CpuAffinityMap {
    /// cpu_id → queue list.
    mapping: HashMap<u32, Vec<u32>>,
    /// Total CPU count.
    num_cpus: u32,
}

impl CpuAffinityMap {
    pub fn new(num_cpus: u32) -> Self {
        Self {
            mapping: HashMap::new(),
            num_cpus: num_cpus.max(1),
        }
    }

    /// Assign a queue to a CPU.
    pub fn assign(&mut self, cpu: u32, queue: u32) {
        if cpu < self.num_cpus {
            self.mapping.entry(cpu).or_default().push(queue);
        }
    }

    /// Get queues assigned to a CPU.
    pub fn queues_for_cpu(&self, cpu: u32) -> &[u32] {
        self.mapping.get(&cpu).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Get the CPU for a queue (first match).
    pub fn cpu_for_queue(&self, queue: u32) -> Option<u32> {
        self.mapping
            .iter()
            .find(|(_, qs)| qs.contains(&queue))
            .map(|(cpu, _)| *cpu)
    }

    /// Round-robin assignment: distribute queues evenly across CPUs.
    pub fn auto_assign(&mut self, num_queues: u32) {
        self.mapping.clear();
        for q in 0..num_queues {
            let cpu = q % self.num_cpus;
            self.mapping.entry(cpu).or_default().push(q);
        }
    }

    /// Number of CPUs with at least one queue assigned.
    pub fn active_cpus(&self) -> usize {
        self.mapping.values().filter(|qs| !qs.is_empty()).count()
    }

    /// Total queues across all CPUs.
    pub fn total_queues(&self) -> usize {
        self.mapping.values().map(|qs| qs.len()).sum()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Feature detector
// ═══════════════════════════════════════════════════════════════════════════

/// Detected eBPF/XDP capabilities of the running kernel.
#[derive(Debug, Clone)]
pub struct EbpfCapabilities {
    /// Kernel version.
    pub kernel_version: Option<KernelVersion>,
    /// XDP generic mode available (always true on 4.8+).
    pub xdp_generic: bool,
    /// XDP native mode available (driver dependent).
    pub xdp_native: bool,
    /// XDP hardware offload available (SmartNIC).
    pub xdp_offload: bool,
    /// BPF ring buffer available (5.8+).
    pub ring_buf: bool,
    /// BPF per-CPU maps available (4.6+).
    pub per_cpu_maps: bool,
    /// BPF BTF (type info) available (5.2+).
    pub btf: bool,
    /// BPF CO-RE (Compile Once, Run Everywhere) available (5.5+).
    pub core: bool,
    /// XDP multi-buffer support (6.0+).
    pub xdp_multi_buffer: bool,
}

impl EbpfCapabilities {
    /// Probe the current system for eBPF capabilities.
    #[cfg(target_os = "linux")]
    pub fn detect() -> Self {
        let kv = Self::detect_kernel_version();
        let (generic, native, offload) = Self::probe_xdp_modes();
        Self {
            ring_buf: kv.map_or(false, |v| v.supports(&KernelVersion::new(5, 8, 0))),
            per_cpu_maps: kv.map_or(false, |v| v.supports(&KernelVersion::new(4, 6, 0))),
            btf: kv.map_or(false, |v| v.supports(&KernelVersion::new(5, 2, 0))),
            core: kv.map_or(false, |v| v.supports(&KernelVersion::new(5, 5, 0))),
            xdp_multi_buffer: kv.map_or(false, |v| v.supports(&KernelVersion::new(6, 0, 0))),
            xdp_generic: generic,
            xdp_native: native,
            xdp_offload: offload,
            kernel_version: kv,
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn detect() -> Self {
        Self {
            kernel_version: None,
            xdp_generic: false,
            xdp_native: false,
            xdp_offload: false,
            ring_buf: false,
            per_cpu_maps: false,
            btf: false,
            core: false,
            xdp_multi_buffer: false,
        }
    }

    #[cfg(target_os = "linux")]
    fn detect_kernel_version() -> Option<KernelVersion> {
        let content = std::fs::read_to_string("/proc/version").ok()?;
        // "Linux version 5.15.0-generic ..."
        let version_str = content.split_whitespace().nth(2)?;
        KernelVersion::parse(version_str)
    }

    #[cfg(target_os = "linux")]
    fn probe_xdp_modes() -> (bool, bool, bool) {
        // Generic XDP is available on 4.8+.
        // Native/offload depend on specific driver support; we check for
        // the bpf() syscall availability as a proxy.
        let bpf_available = std::path::Path::new("/sys/fs/bpf").exists();
        (bpf_available, false, false) // Conservative: only generic until driver probe
    }

    /// Check if any XDP mode is available.
    pub fn has_xdp(&self) -> bool {
        self.xdp_generic || self.xdp_native || self.xdp_offload
    }

    /// Best available XDP mode.
    pub fn best_xdp_mode(&self) -> Option<XdpMode> {
        if self.xdp_offload {
            Some(XdpMode::Offload)
        } else if self.xdp_native {
            Some(XdpMode::Native)
        } else if self.xdp_generic {
            Some(XdpMode::Generic)
        } else {
            None
        }
    }

    /// Build from explicit values (for testing).
    pub fn from_values(
        kernel_version: Option<KernelVersion>,
        xdp_generic: bool,
        xdp_native: bool,
        xdp_offload: bool,
    ) -> Self {
        let kv = kernel_version;
        Self {
            ring_buf: kv.map_or(false, |v| v.supports(&KernelVersion::new(5, 8, 0))),
            per_cpu_maps: kv.map_or(false, |v| v.supports(&KernelVersion::new(4, 6, 0))),
            btf: kv.map_or(false, |v| v.supports(&KernelVersion::new(5, 2, 0))),
            core: kv.map_or(false, |v| v.supports(&KernelVersion::new(5, 5, 0))),
            xdp_multi_buffer: kv.map_or(false, |v| v.supports(&KernelVersion::new(6, 0, 0))),
            xdp_generic,
            xdp_native,
            xdp_offload,
            kernel_version: kv,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Backend map entry
// ═══════════════════════════════════════════════════════════════════════════

/// A backend entry in the eBPF steering map.
#[derive(Debug, Clone)]
pub struct BackendEntry {
    /// Backend index (position in the map).
    pub index: u32,
    /// IPv4 address as 4 bytes.
    pub ipv4: [u8; 4],
    /// Destination port.
    pub port: u16,
    /// Weight for weighted distribution.
    pub weight: u16,
    /// Is this backend healthy?
    pub healthy: bool,
}

impl BackendEntry {
    pub fn new(index: u32, ipv4: [u8; 4], port: u16) -> Self {
        Self {
            index,
            ipv4,
            port,
            weight: 1,
            healthy: true,
        }
    }

    pub fn with_weight(mut self, weight: u16) -> Self {
        self.weight = weight.max(1);
        self
    }

    pub fn set_healthy(&mut self, healthy: bool) {
        self.healthy = healthy;
    }

    /// Format the IPv4 address as a string.
    pub fn ip_string(&self) -> String {
        format!("{}.{}.{}.{}", self.ipv4[0], self.ipv4[1], self.ipv4[2], self.ipv4[3])
    }

    /// Serialize to bytes for eBPF map value (fixed 12-byte layout).
    /// Layout: [ip:4][port:2][weight:2][flags:1][pad:3]
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&self.ipv4);
        buf[4..6].copy_from_slice(&self.port.to_le_bytes());
        buf[6..8].copy_from_slice(&self.weight.to_le_bytes());
        buf[8] = if self.healthy { 1 } else { 0 };
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(index: u32, data: &[u8; 12]) -> Self {
        let mut ipv4 = [0u8; 4];
        ipv4.copy_from_slice(&data[0..4]);
        let port = u16::from_le_bytes([data[4], data[5]]);
        let weight = u16::from_le_bytes([data[6], data[7]]);
        let healthy = data[8] != 0;
        Self {
            index,
            ipv4,
            port,
            weight,
            healthy,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Backend map
// ═══════════════════════════════════════════════════════════════════════════

/// Userspace representation of the eBPF backend map.
/// This is synced to the kernel map via bpf_map_update_elem.
pub struct BackendMap {
    entries: Vec<BackendEntry>,
    max_backends: usize,
    generation: u64,
    /// Generation that was current at the last successful sync.
    /// Used to detect convergence: needs_sync() is false once this equals `generation`.
    synced_generation: u64,
    last_sync: Option<Instant>,
}

impl BackendMap {
    pub fn new(max_backends: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_backends: max_backends.max(1),
            generation: 0,
            synced_generation: 0,
            last_sync: None,
        }
    }

    /// Add or update a backend. Returns false if at capacity and not updating.
    pub fn upsert(&mut self, entry: BackendEntry) -> bool {
        if let Some(existing) = self.entries.iter_mut().find(|e| e.index == entry.index) {
            *existing = entry;
            self.generation += 1;
            true
        } else if self.entries.len() < self.max_backends {
            self.entries.push(entry);
            self.generation += 1;
            true
        } else {
            false
        }
    }

    /// Remove a backend by index.
    pub fn remove(&mut self, index: u32) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.index != index);
        if self.entries.len() < before {
            self.generation += 1;
            true
        } else {
            false
        }
    }

    /// Mark a backend as unhealthy.
    pub fn mark_unhealthy(&mut self, index: u32) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.index == index) {
            entry.healthy = false;
            self.generation += 1;
        }
    }

    /// Mark a backend as healthy.
    pub fn mark_healthy(&mut self, index: u32) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.index == index) {
            entry.healthy = true;
            self.generation += 1;
        }
    }

    /// Get healthy backends only.
    pub fn healthy_backends(&self) -> Vec<&BackendEntry> {
        self.entries.iter().filter(|e| e.healthy).collect()
    }

    /// Total healthy weight.
    pub fn healthy_weight(&self) -> u32 {
        self.entries
            .iter()
            .filter(|e| e.healthy)
            .map(|e| e.weight as u32)
            .sum()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Mark that a sync to kernel map was performed.
    pub fn mark_synced(&mut self) {
        // BUG FIX: previously mark_synced() ignored `generation`, so needs_sync()
        // (which tested `generation > 0`) stayed true forever and sync
        // de-duplication never converged. Record the generation we just synced.
        self.synced_generation = self.generation;
        self.last_sync = Some(Instant::now());
    }

    /// Time since last sync.
    pub fn time_since_sync(&self) -> Option<Duration> {
        self.last_sync.map(|t| t.elapsed())
    }

    /// Check if a sync is needed (generation changed since last sync).
    pub fn needs_sync(&self) -> bool {
        // BUG FIX: compare against the generation captured at the last sync
        // instead of `generation > 0` (which never returned to false after any
        // mutation). Converges once a sync has caught up to the latest mutation.
        self.last_sync.is_none() || self.generation != self.synced_generation
    }

    /// Serialize all entries for bulk map update.
    pub fn serialize_all(&self) -> Vec<[u8; 12]> {
        self.entries.iter().map(|e| e.to_bytes()).collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Global metrics
// ═══════════════════════════════════════════════════════════════════════════

pub struct EbpfMetrics {
    pub map_updates: AtomicU64,
    pub map_update_errors: AtomicU64,
    pub program_loads: AtomicU64,
    pub program_load_errors: AtomicU64,
    pub rule_matches: AtomicU64,
}

static EBPF_METRICS: EbpfMetrics = EbpfMetrics {
    map_updates: AtomicU64::new(0),
    map_update_errors: AtomicU64::new(0),
    program_loads: AtomicU64::new(0),
    program_load_errors: AtomicU64::new(0),
    rule_matches: AtomicU64::new(0),
};

pub fn ebpf_metrics() -> &'static EbpfMetrics {
    &EBPF_METRICS
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── XDP mode ──────────────────────────────────────────────────────

    #[test]
    fn xdp_mode_roundtrip() {
        assert_eq!(XdpMode::from_u8(0), XdpMode::Generic);
        assert_eq!(XdpMode::from_u8(1), XdpMode::Native);
        assert_eq!(XdpMode::from_u8(2), XdpMode::Offload);
        assert_eq!(XdpMode::from_u8(99), XdpMode::Generic); // default
    }

    #[test]
    fn xdp_mode_labels() {
        assert_eq!(XdpMode::Generic.label(), "generic");
        assert_eq!(XdpMode::Native.label(), "native");
        assert_eq!(XdpMode::Offload.label(), "offload");
    }

    // ── XDP action ────────────────────────────────────────────────────

    #[test]
    fn xdp_action_roundtrip() {
        assert_eq!(XdpAction::from_u32(0), XdpAction::Aborted);
        assert_eq!(XdpAction::from_u32(1), XdpAction::Drop);
        assert_eq!(XdpAction::from_u32(2), XdpAction::Pass);
        assert_eq!(XdpAction::from_u32(3), XdpAction::Tx);
        assert_eq!(XdpAction::from_u32(4), XdpAction::Redirect);
        assert_eq!(XdpAction::from_u32(255), XdpAction::Aborted);
    }

    // ── Map type ──────────────────────────────────────────────────────

    #[test]
    fn map_type_roundtrip() {
        for v in 0..=6 {
            let mt = MapType::from_u8(v);
            assert!(!mt.label().is_empty());
        }
        assert_eq!(MapType::from_u8(255), MapType::Hash);
    }

    #[test]
    fn map_type_per_cpu() {
        assert!(MapType::PerCpuArray.is_per_cpu());
        assert!(MapType::CpuMap.is_per_cpu());
        assert!(!MapType::Hash.is_per_cpu());
        assert!(!MapType::Array.is_per_cpu());
        assert!(!MapType::RingBuf.is_per_cpu());
    }

    // ── Map descriptor ────────────────────────────────────────────────

    #[test]
    fn map_descriptor_memory() {
        let md = MapDescriptor::new("test", MapType::Hash, 4, 8, 1000);
        assert_eq!(md.estimated_memory(), 12 * 1000);
    }

    #[test]
    fn map_descriptor_flags() {
        let md = MapDescriptor::new("test", MapType::Hash, 4, 4, 10).with_flags(0x01);
        assert_eq!(md.flags, 0x01);
    }

    // ── Program descriptor ────────────────────────────────────────────

    #[test]
    fn program_descriptor_defaults() {
        let pd = ProgramDescriptor::new("lb", "/path/lb.o", "xdp");
        assert_eq!(pd.attach_mode, XdpMode::Generic);
        assert_eq!(pd.license, "GPL");
        assert_eq!(pd.min_kernel, KernelVersion::new(5, 15, 0));
    }

    #[test]
    fn program_descriptor_map_memory() {
        let pd = ProgramDescriptor::new("lb", "/path/lb.o", "xdp")
            .with_map(MapDescriptor::new("backends", MapType::Hash, 4, 12, 100))
            .with_map(MapDescriptor::new("stats", MapType::PerCpuArray, 4, 8, 16));
        assert_eq!(pd.total_map_memory(), (4 + 12) * 100 + (4 + 8) * 16);
    }

    #[test]
    fn program_descriptor_builder() {
        let pd = ProgramDescriptor::new("test", "/test.o", "xdp/ingress")
            .with_mode(XdpMode::Native)
            .with_license("Dual BSD/GPL")
            .with_min_kernel(6, 1, 0);
        assert_eq!(pd.attach_mode, XdpMode::Native);
        assert_eq!(pd.license, "Dual BSD/GPL");
        assert_eq!(pd.min_kernel, KernelVersion::new(6, 1, 0));
    }

    // ── Kernel version ────────────────────────────────────────────────

    #[test]
    fn kernel_version_parse() {
        let v = KernelVersion::parse("5.15.0-generic").unwrap();
        assert_eq!(v, KernelVersion::new(5, 15, 0));
    }

    #[test]
    fn kernel_version_parse_no_patch() {
        let v = KernelVersion::parse("6.1").unwrap();
        assert_eq!(v, KernelVersion::new(6, 1, 0));
    }

    #[test]
    fn kernel_version_comparison() {
        let v5 = KernelVersion::new(5, 15, 0);
        let v6 = KernelVersion::new(6, 1, 0);
        assert!(v6 > v5);
        assert!(v5.supports(&KernelVersion::new(5, 10, 0)));
        assert!(!v5.supports(&KernelVersion::new(6, 0, 0)));
    }

    #[test]
    fn kernel_version_display() {
        let v = KernelVersion::new(5, 15, 3);
        assert_eq!(format!("{}", v), "5.15.3");
    }

    // ── Match spec ────────────────────────────────────────────────────

    #[test]
    fn match_spec_any() {
        let m = MatchSpec::any();
        assert_eq!(m.specificity(), 0);
    }

    #[test]
    fn match_spec_tcp_port() {
        let m = MatchSpec::tcp_port(443);
        assert_eq!(m.dst_port, Some(443));
        assert_eq!(m.protocol, Some(6));
        assert_eq!(m.specificity(), 2);
    }

    #[test]
    fn match_spec_udp_port() {
        let m = MatchSpec::udp_port(53);
        assert_eq!(m.dst_port, Some(53));
        assert_eq!(m.protocol, Some(17));
    }

    // ── Steering table ────────────────────────────────────────────────

    #[test]
    fn steering_table_insert_and_lookup() {
        let mut t = SteeringTable::new(10);
        let rule = SteeringRule::new(
            1, 100,
            MatchSpec::tcp_port(443),
            SteeringAction::ToCpu(0),
        );
        assert!(t.insert(rule));
        assert_eq!(t.len(), 1);

        let found = t.lookup(None, Some(443), Some(6));
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, 1);
    }

    #[test]
    fn steering_table_priority_order() {
        let mut t = SteeringTable::new(10);
        t.insert(SteeringRule::new(1, 200, MatchSpec::any(), SteeringAction::Pass));
        t.insert(SteeringRule::new(2, 100, MatchSpec::tcp_port(443), SteeringAction::ToCpu(0)));

        // Rule 2 (priority 100) comes first.
        let rules = t.active_rules();
        assert_eq!(rules[0].id, 2);
        assert_eq!(rules[1].id, 1);
    }

    #[test]
    fn steering_table_remove() {
        let mut t = SteeringTable::new(10);
        t.insert(SteeringRule::new(1, 100, MatchSpec::any(), SteeringAction::Pass));
        assert!(t.remove(1));
        assert!(t.is_empty());
        assert!(!t.remove(1)); // Already removed.
    }

    #[test]
    fn steering_table_disable_rule() {
        let mut t = SteeringTable::new(10);
        let mut rule = SteeringRule::new(1, 100, MatchSpec::tcp_port(80), SteeringAction::ToCpu(1));
        rule.disable();
        t.insert(rule);

        // Disabled rule should not match.
        let found = t.lookup(None, Some(80), Some(6));
        assert!(found.is_none());
    }

    #[test]
    fn steering_table_capacity() {
        let mut t = SteeringTable::new(8); // min clamped to 8
        for i in 0..8 {
            assert!(t.insert(SteeringRule::new(i, i as u16, MatchSpec::any(), SteeringAction::Pass)));
        }
        // At capacity.
        assert!(!t.insert(SteeringRule::new(99, 99, MatchSpec::any(), SteeringAction::Pass)));
    }

    // Regression: updating an existing rule id must succeed even when the table
    // is exactly at capacity. Previously the capacity check ran before the dedup
    // retain, so the live update was silently dropped and stale steering remained.
    #[test]
    fn steering_table_update_at_capacity() {
        let mut t = SteeringTable::new(8); // min clamped to 8
        for i in 0..8 {
            assert!(t.insert(SteeringRule::new(i, i as u16, MatchSpec::any(), SteeringAction::Pass)));
        }
        assert_eq!(t.len(), 8); // full

        // Re-point rule 0 (an update of an existing id) while at capacity.
        assert!(
            t.insert(SteeringRule::new(0, 0, MatchSpec::any(), SteeringAction::Drop)),
            "update of existing id must succeed at capacity"
        );
        assert_eq!(t.len(), 8, "update must not grow the table");

        // The update must have been applied (action is now Drop for id 0).
        let updated = t
            .all_rules()
            .iter()
            .find(|r| r.id == 0)
            .expect("rule 0 still present");
        assert!(matches!(updated.action, SteeringAction::Drop));

        // A genuinely new id is still rejected when full.
        assert!(!t.insert(SteeringRule::new(99, 99, MatchSpec::any(), SteeringAction::Pass)));
    }

    #[test]
    fn steering_table_cidr_match() {
        let mut t = SteeringTable::new(10);
        t.insert(SteeringRule::new(
            1, 100,
            MatchSpec::from_prefix("10.0.0.0/8"),
            SteeringAction::ToCpu(2),
        ));

        assert!(t.lookup(Some("10.1.2.3"), None, None).is_some());
        assert!(t.lookup(Some("10.255.0.1"), None, None).is_some());
        assert!(t.lookup(Some("192.168.1.1"), None, None).is_none());
    }

    // Regression: cidr_contains must honor the /N mask instead of breaking on
    // the first zero octet. /24 must exclude addresses outside the network
    // (no false positive), and /16 must include addresses inside it that differ
    // in the third octet (no false negative).
    #[test]
    fn steering_table_cidr_honors_prefix_length() {
        // /24 false-positive case: 10.0.99.5 is OUTSIDE 10.0.0.0/24.
        let mut t24 = SteeringTable::new(10);
        t24.insert(SteeringRule::new(
            1, 100,
            MatchSpec::from_prefix("10.0.0.0/24"),
            SteeringAction::ToCpu(1),
        ));
        assert!(
            t24.lookup(Some("10.0.0.7"), None, None).is_some(),
            "10.0.0.7 is inside 10.0.0.0/24"
        );
        assert!(
            t24.lookup(Some("10.0.99.5"), None, None).is_none(),
            "10.0.99.5 must NOT match 10.0.0.0/24 (false-positive regression)"
        );

        // /16 false-negative case: 10.20.99.5 IS inside 10.20.0.0/16.
        let mut t16 = SteeringTable::new(10);
        t16.insert(SteeringRule::new(
            2, 100,
            MatchSpec::from_prefix("10.20.30.0/16"),
            SteeringAction::ToCpu(2),
        ));
        assert!(
            t16.lookup(Some("10.20.99.5"), None, None).is_some(),
            "10.20.99.5 must match 10.20.0.0/16 (false-negative regression)"
        );
        assert!(
            t16.lookup(Some("10.21.0.1"), None, None).is_none(),
            "10.21.0.1 is outside 10.20.0.0/16"
        );

        // /0 matches everything; full /32 matches only the exact host.
        let mut t0 = SteeringTable::new(10);
        t0.insert(SteeringRule::new(
            3, 100,
            MatchSpec::from_prefix("0.0.0.0/0"),
            SteeringAction::Pass,
        ));
        assert!(t0.lookup(Some("203.0.113.9"), None, None).is_some());

        let mut t32 = SteeringTable::new(10);
        t32.insert(SteeringRule::new(
            4, 100,
            MatchSpec::from_prefix("192.168.1.1/32"),
            SteeringAction::Drop,
        ));
        assert!(t32.lookup(Some("192.168.1.1"), None, None).is_some());
        assert!(t32.lookup(Some("192.168.1.2"), None, None).is_none());
    }

    #[test]
    fn steering_table_upsert_same_id() {
        let mut t = SteeringTable::new(10);
        t.insert(SteeringRule::new(1, 100, MatchSpec::any(), SteeringAction::Pass));
        t.insert(SteeringRule::new(1, 50, MatchSpec::any(), SteeringAction::Drop)); // Update.
        assert_eq!(t.len(), 1);
        let rules = t.all_rules();
        assert!(matches!(rules[0].action, SteeringAction::Drop));
    }

    // ── Program stats ─────────────────────────────────────────────────

    #[test]
    fn program_stats_record() {
        let stats = ProgramStats::new();
        stats.record_packet(1500, XdpAction::Pass);
        stats.record_packet(64, XdpAction::Drop);
        stats.record_packet(1500, XdpAction::Redirect);
        stats.record_packet(0, XdpAction::Aborted);

        let snap = stats.snapshot();
        assert_eq!(snap.packets_processed, 4);
        assert_eq!(snap.bytes_processed, 3064);
        assert_eq!(snap.packets_passed, 1);
        assert_eq!(snap.packets_dropped, 1);
        assert_eq!(snap.packets_redirected, 1);
        assert_eq!(snap.errors, 1);
    }

    #[test]
    fn stats_snapshot_rates() {
        let stats = ProgramStats::new();
        for _ in 0..10 {
            stats.record_packet(100, XdpAction::Pass);
        }
        stats.record_packet(100, XdpAction::Drop);

        let snap = stats.snapshot();
        assert!((snap.drop_rate() - 1.0 / 11.0).abs() < 0.01);
        assert!((snap.avg_packet_size() - 100.0).abs() < 0.01);
    }

    #[test]
    fn stats_snapshot_empty() {
        let snap = StatsSnapshot {
            packets_processed: 0,
            bytes_processed: 0,
            packets_dropped: 0,
            packets_redirected: 0,
            packets_passed: 0,
            errors: 0,
        };
        assert_eq!(snap.drop_rate(), 0.0);
        assert_eq!(snap.redirect_rate(), 0.0);
        assert_eq!(snap.avg_packet_size(), 0.0);
    }

    // ── CPU affinity map ──────────────────────────────────────────────

    #[test]
    fn cpu_affinity_manual_assign() {
        let mut m = CpuAffinityMap::new(4);
        m.assign(0, 0);
        m.assign(0, 1);
        m.assign(1, 2);

        assert_eq!(m.queues_for_cpu(0), &[0, 1]);
        assert_eq!(m.queues_for_cpu(1), &[2]);
        assert_eq!(m.queues_for_cpu(2), &[] as &[u32]); // No queues assigned.
    }

    #[test]
    fn cpu_affinity_auto_assign() {
        let mut m = CpuAffinityMap::new(4);
        m.auto_assign(8);

        assert_eq!(m.active_cpus(), 4);
        assert_eq!(m.total_queues(), 8);
        // Each CPU gets 2 queues.
        assert_eq!(m.queues_for_cpu(0).len(), 2);
    }

    #[test]
    fn cpu_affinity_cpu_for_queue() {
        let mut m = CpuAffinityMap::new(4);
        m.auto_assign(8);
        assert_eq!(m.cpu_for_queue(0), Some(0));
        assert_eq!(m.cpu_for_queue(3), Some(3));
        assert_eq!(m.cpu_for_queue(4), Some(0)); // Wraps around.
    }

    #[test]
    fn cpu_affinity_ignores_invalid_cpu() {
        let mut m = CpuAffinityMap::new(2);
        m.assign(5, 0); // CPU 5 >= num_cpus (2), should be ignored.
        assert_eq!(m.total_queues(), 0);
    }

    // ── Backend entry ─────────────────────────────────────────────────

    #[test]
    fn backend_entry_serialize_roundtrip() {
        let entry = BackendEntry::new(0, [10, 0, 1, 5], 8080).with_weight(3);
        let bytes = entry.to_bytes();
        let decoded = BackendEntry::from_bytes(0, &bytes);

        assert_eq!(decoded.ipv4, [10, 0, 1, 5]);
        assert_eq!(decoded.port, 8080);
        assert_eq!(decoded.weight, 3);
        assert!(decoded.healthy);
    }

    #[test]
    fn backend_entry_unhealthy() {
        let mut entry = BackendEntry::new(0, [192, 168, 1, 1], 443);
        entry.set_healthy(false);
        let bytes = entry.to_bytes();
        let decoded = BackendEntry::from_bytes(0, &bytes);
        assert!(!decoded.healthy);
    }

    #[test]
    fn backend_entry_ip_string() {
        let entry = BackendEntry::new(0, [10, 0, 1, 100], 80);
        assert_eq!(entry.ip_string(), "10.0.1.100");
    }

    // ── Backend map ───────────────────────────────────────────────────

    #[test]
    fn backend_map_upsert_and_remove() {
        let mut m = BackendMap::new(10);
        assert!(m.upsert(BackendEntry::new(0, [10, 0, 0, 1], 80)));
        assert!(m.upsert(BackendEntry::new(1, [10, 0, 0, 2], 80)));
        assert_eq!(m.len(), 2);

        assert!(m.remove(0));
        assert_eq!(m.len(), 1);
        assert!(!m.remove(0)); // Already removed.
    }

    #[test]
    fn backend_map_capacity() {
        let mut m = BackendMap::new(2);
        assert!(m.upsert(BackendEntry::new(0, [10, 0, 0, 1], 80)));
        assert!(m.upsert(BackendEntry::new(1, [10, 0, 0, 2], 80)));
        assert!(!m.upsert(BackendEntry::new(2, [10, 0, 0, 3], 80))); // At capacity.
    }

    #[test]
    fn backend_map_health() {
        let mut m = BackendMap::new(10);
        m.upsert(BackendEntry::new(0, [10, 0, 0, 1], 80));
        m.upsert(BackendEntry::new(1, [10, 0, 0, 2], 80));

        assert_eq!(m.healthy_backends().len(), 2);
        m.mark_unhealthy(0);
        assert_eq!(m.healthy_backends().len(), 1);
        m.mark_healthy(0);
        assert_eq!(m.healthy_backends().len(), 2);
    }

    #[test]
    fn backend_map_healthy_weight() {
        let mut m = BackendMap::new(10);
        m.upsert(BackendEntry::new(0, [10, 0, 0, 1], 80).with_weight(3));
        m.upsert(BackendEntry::new(1, [10, 0, 0, 2], 80).with_weight(5));
        assert_eq!(m.healthy_weight(), 8);

        m.mark_unhealthy(1);
        assert_eq!(m.healthy_weight(), 3);
    }

    #[test]
    fn backend_map_generation() {
        let mut m = BackendMap::new(10);
        assert_eq!(m.generation(), 0);
        m.upsert(BackendEntry::new(0, [10, 0, 0, 1], 80));
        assert_eq!(m.generation(), 1);
        m.mark_unhealthy(0);
        assert_eq!(m.generation(), 2);
    }

    // Regression: needs_sync() must converge to false after mark_synced(), and
    // flip back to true only after a subsequent mutation. Previously needs_sync
    // tested `generation > 0`, so it stayed true forever after any mutation.
    #[test]
    fn backend_map_needs_sync_converges_after_mark_synced() {
        let mut m = BackendMap::new(10);
        // Fresh map with no sync yet: a sync is required.
        assert!(m.needs_sync());

        m.upsert(BackendEntry::new(0, [10, 0, 0, 1], 80));
        assert!(m.needs_sync(), "mutation should require a sync");

        m.mark_synced();
        assert!(
            !m.needs_sync(),
            "needs_sync must be false immediately after mark_synced (de-dup must converge)"
        );

        // A further mutation re-arms the sync flag.
        m.mark_unhealthy(0);
        assert!(m.needs_sync(), "post-sync mutation must require another sync");

        m.mark_synced();
        assert!(!m.needs_sync(), "second sync must converge again");
    }

    #[test]
    fn backend_map_serialize() {
        let mut m = BackendMap::new(10);
        m.upsert(BackendEntry::new(0, [10, 0, 0, 1], 80));
        m.upsert(BackendEntry::new(1, [10, 0, 0, 2], 8080));

        let serialized = m.serialize_all();
        assert_eq!(serialized.len(), 2);
        assert_eq!(serialized[0].len(), 12);
    }

    // ── Feature detection ─────────────────────────────────────────────

    #[test]
    fn capabilities_detect_runs() {
        let caps = EbpfCapabilities::detect();
        // On macOS/non-Linux, everything is false.
        #[cfg(not(target_os = "linux"))]
        {
            assert!(!caps.has_xdp());
            assert!(caps.best_xdp_mode().is_none());
        }
        let _ = caps; // Use on Linux too.
    }

    #[test]
    fn capabilities_from_values() {
        let caps = EbpfCapabilities::from_values(
            Some(KernelVersion::new(6, 1, 0)),
            true, true, false,
        );
        assert!(caps.has_xdp());
        assert_eq!(caps.best_xdp_mode(), Some(XdpMode::Native));
        assert!(caps.ring_buf);
        assert!(caps.btf);
        assert!(caps.core);
        assert!(caps.xdp_multi_buffer);
    }

    #[test]
    fn capabilities_old_kernel() {
        let caps = EbpfCapabilities::from_values(
            Some(KernelVersion::new(4, 18, 0)),
            true, false, false,
        );
        assert!(caps.per_cpu_maps); // 4.6+
        assert!(!caps.ring_buf);    // requires 5.8+
        assert!(!caps.btf);        // requires 5.2+
        assert!(!caps.core);       // requires 5.5+
    }

    // ── Global toggle ─────────────────────────────────────────────────

    #[test]
    fn global_toggle() {
        set_ebpf_enabled(true);
        assert!(is_ebpf_enabled());
    }

    // ── Metrics (delta-based) ─────────────────────────────────────────

    #[test]
    fn global_metrics_accessible() {
        let m = ebpf_metrics();
        let before = m.map_updates.load(Ordering::Relaxed);
        m.map_updates.fetch_add(1, Ordering::Relaxed);
        let after = m.map_updates.load(Ordering::Relaxed);
        assert!(after >= before + 1);
    }
}
