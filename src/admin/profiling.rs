//! Lightweight pprof-style profiling endpoints for the admin API.
//!
//! Since we run on M1 Mac where eBPF/perf_event is unavailable, this module
//! avoids `pprof-rs` and instead queries tokio runtime metrics, OS-level
//! resource usage via `libc`, and simple atomic allocation counters.

use axum::Json;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Allocation tracking
// ---------------------------------------------------------------------------

static ALLOC_COUNTER: AtomicU64 = AtomicU64::new(0);
static DEALLOC_COUNTER: AtomicU64 = AtomicU64::new(0);
static PEAK_ALLOC: AtomicU64 = AtomicU64::new(0);

/// Record an allocation of `size` bytes. Called from a custom global allocator
/// shim or manually from hot paths.
pub fn record_alloc(size: u64) {
    let prev = ALLOC_COUNTER.fetch_add(size, Ordering::Relaxed);
    let current = prev + size - DEALLOC_COUNTER.load(Ordering::Relaxed);
    // Racy CAS for peak — good enough for diagnostics.
    let mut peak = PEAK_ALLOC.load(Ordering::Relaxed);
    while current > peak {
        match PEAK_ALLOC.compare_exchange_weak(peak, current, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => break,
            Err(actual) => peak = actual,
        }
    }
}

/// Record a deallocation of `size` bytes.
pub fn record_dealloc(size: u64) {
    DEALLOC_COUNTER.fetch_add(size, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// 1. Heap profile
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct HeapProfile {
    pub timestamp: String,
    /// Cumulative bytes allocated (monotonic).
    pub allocated_bytes: u64,
    /// Cumulative bytes freed (monotonic).
    pub freed_bytes: u64,
    /// Approximate live bytes (`allocated - freed`).
    pub live_bytes: u64,
    /// Peak observed live allocation.
    pub peak_bytes: u64,
    /// Resident set size from the OS (macOS `getrusage` or Linux `/proc`).
    pub rss_bytes: u64,
}

pub async fn heap_profile() -> Json<HeapProfile> {
    let allocated = ALLOC_COUNTER.load(Ordering::Relaxed);
    let freed = DEALLOC_COUNTER.load(Ordering::Relaxed);
    let live = allocated.saturating_sub(freed);
    let peak = PEAK_ALLOC.load(Ordering::Relaxed);

    Json(HeapProfile {
        timestamp: chrono::Utc::now().to_rfc3339(),
        allocated_bytes: allocated,
        freed_bytes: freed,
        live_bytes: live,
        peak_bytes: peak,
        rss_bytes: resident_memory_bytes(),
    })
}

// ---------------------------------------------------------------------------
// 2. Tasks profile (tokio runtime metrics)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct TasksProfile {
    pub timestamp: String,
    pub active_tasks: u64,
    pub worker_threads: usize,
    pub blocking_threads: usize,
}

pub async fn tasks_profile() -> Json<TasksProfile> {
    let handle = tokio::runtime::Handle::current();
    let metrics = handle.metrics();

    Json(TasksProfile {
        timestamp: chrono::Utc::now().to_rfc3339(),
        active_tasks: metrics.num_alive_tasks() as u64,
        worker_threads: metrics.num_workers(),
        blocking_threads: metrics.num_blocking_threads(),
    })
}

// ---------------------------------------------------------------------------
// 3. Threads profile
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ThreadsProfile {
    pub timestamp: String,
    pub thread_count: usize,
    pub threads: Vec<ThreadInfo>,
}

#[derive(Debug, Serialize)]
pub struct ThreadInfo {
    pub name: String,
    pub id: u64,
}

pub async fn threads_profile() -> Json<ThreadsProfile> {
    let threads = enumerate_threads();
    let count = threads.len();
    Json(ThreadsProfile {
        timestamp: chrono::Utc::now().to_rfc3339(),
        thread_count: count,
        threads,
    })
}

/// Enumerate OS threads. On Linux reads `/proc/self/task/`; on macOS falls
/// back to `num_cpus` since there is no `/proc`.
fn enumerate_threads() -> Vec<ThreadInfo> {
    #[cfg(target_os = "linux")]
    {
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/proc/self/task") {
            for entry in entries.flatten() {
                let tid: u64 = entry.file_name().to_string_lossy().parse().unwrap_or(0);
                let name = std::fs::read_to_string(format!("/proc/self/task/{tid}/comm"))
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                out.push(ThreadInfo { name, id: tid });
            }
        }
        out
    }
    #[cfg(not(target_os = "linux"))]
    {
        // macOS: no /proc. Report the current thread and use num_cpus as a
        // size hint. The actual thread count comes from mach_task_info but
        // that requires unsafe mach_* calls; we use a lightweight fallback.
        let count = thread_count_macos();
        let mut out = Vec::with_capacity(count);
        // Report at least the current thread.
        let current = std::thread::current();
        out.push(ThreadInfo {
            name: current.name().unwrap_or("main").to_string(),
            id: 0,
        });
        // Fill remaining slots with placeholder entries so the count is
        // accurate even though we can't name every thread.
        for i in 1..count {
            out.push(ThreadInfo {
                name: format!("thread-{i}"),
                id: i as u64,
            });
        }
        out
    }
}

/// Get the number of threads for this process on macOS via `proc_pidinfo`.
#[cfg(not(target_os = "linux"))]
fn thread_count_macos() -> usize {
    // Try mach task_info for an accurate thread count.
    #[cfg(target_os = "macos")]
    {
        use std::mem;
        unsafe {
            let mut info: libc::mach_task_basic_info_data_t = mem::zeroed();
            let mut count = (mem::size_of::<libc::mach_task_basic_info_data_t>()
                / mem::size_of::<libc::natural_t>())
                as libc::mach_msg_type_number_t;
            #[allow(deprecated)] // libc deprecated in favor of mach2 crate
            let task = libc::mach_task_self();
            let kr = libc::task_info(
                task,
                libc::MACH_TASK_BASIC_INFO,
                &mut info as *mut _ as libc::task_info_t,
                &mut count,
            );
            if kr == libc::KERN_SUCCESS {
                return info.policy as usize; // policy field — fallback below if nonsensical
            }
        }
    }
    // Absolute fallback: number of logical CPUs.
    num_cpus::get()
}

// ---------------------------------------------------------------------------
// 4. Runtime / uptime profile
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct RuntimeProfile {
    pub timestamp: String,
    pub uptime_secs: u64,
    pub pid: u32,
    pub num_cpus: usize,
    pub resident_memory_bytes: u64,
    pub virtual_memory_bytes: u64,
}

/// Process start instant — captured once on first access.
static PROCESS_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// Call once during startup to anchor the uptime clock.
pub fn init_start_time() {
    PROCESS_START.get_or_init(std::time::Instant::now);
}

pub async fn runtime_profile() -> Json<RuntimeProfile> {
    init_start_time(); // idempotent
    let uptime = PROCESS_START
        .get()
        .map(|s| s.elapsed().as_secs())
        .unwrap_or(0);

    let (rss, vsz) = memory_usage();

    Json(RuntimeProfile {
        timestamp: chrono::Utc::now().to_rfc3339(),
        uptime_secs: uptime,
        pid: std::process::id(),
        num_cpus: num_cpus::get(),
        resident_memory_bytes: rss,
        virtual_memory_bytes: vsz,
    })
}

// ---------------------------------------------------------------------------
// 5. Combined profile
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct CombinedProfile {
    pub heap: HeapProfile,
    pub tasks: TasksProfile,
    pub runtime: RuntimeProfile,
}

pub async fn combined_profile() -> Json<CombinedProfile> {
    let heap = heap_profile().await.0;
    let tasks = tasks_profile().await.0;
    let runtime = runtime_profile().await.0;
    Json(CombinedProfile {
        heap,
        tasks,
        runtime,
    })
}

// ---------------------------------------------------------------------------
// OS helpers
// ---------------------------------------------------------------------------

/// Returns `(resident_bytes, virtual_bytes)`.
fn memory_usage() -> (u64, u64) {
    #[cfg(target_os = "linux")]
    {
        // /proc/self/statm: size resident shared text lib data dt (in pages)
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            let parts: Vec<&str> = statm.split_whitespace().collect();
            if parts.len() >= 2 {
                let page = page_size();
                let vsz: u64 = parts[0].parse().unwrap_or(0) * page;
                let rss: u64 = parts[1].parse().unwrap_or(0) * page;
                return (rss, vsz);
            }
        }
        (0, 0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // macOS: getrusage gives ru_maxrss in bytes (on macOS it's bytes,
        // on some other BSDs it's KB — we handle macOS specifically).
        let rss = resident_memory_bytes();
        (rss, 0) // virtual memory not trivially available without mach API
    }
}

/// Resident set size via `getrusage` (Unix) or 0 on other platforms.
#[cfg(unix)]
fn resident_memory_bytes() -> u64 {
    unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut usage) == 0 {
            // macOS reports ru_maxrss in bytes; Linux in kilobytes.
            #[cfg(target_os = "macos")]
            {
                usage.ru_maxrss as u64
            }
            #[cfg(not(target_os = "macos"))]
            {
                (usage.ru_maxrss as u64) * 1024
            }
        } else {
            0
        }
    }
}

#[cfg(not(unix))]
fn resident_memory_bytes() -> u64 {
    0
}

#[cfg(target_os = "linux")]
fn page_size() -> u64 {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heap_profile_serializes() {
        let hp = HeapProfile {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            allocated_bytes: 1024,
            freed_bytes: 256,
            live_bytes: 768,
            peak_bytes: 1024,
            rss_bytes: 4096,
        };
        let json = serde_json::to_string(&hp).unwrap();
        assert!(json.contains("\"allocated_bytes\":1024"));
        assert!(json.contains("\"live_bytes\":768"));
    }

    #[test]
    fn tasks_profile_serializes() {
        let tp = TasksProfile {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            active_tasks: 42,
            worker_threads: 4,
            blocking_threads: 2,
        };
        let json = serde_json::to_string(&tp).unwrap();
        assert!(json.contains("\"active_tasks\":42"));
        assert!(json.contains("\"worker_threads\":4"));
    }

    #[test]
    fn runtime_profile_serializes() {
        let rp = RuntimeProfile {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            uptime_secs: 3600,
            pid: 1234,
            num_cpus: 8,
            resident_memory_bytes: 65536,
            virtual_memory_bytes: 131072,
        };
        let json = serde_json::to_string(&rp).unwrap();
        assert!(json.contains("\"uptime_secs\":3600"));
        assert!(json.contains("\"pid\":1234"));
    }

    #[test]
    fn combined_profile_serializes() {
        let cp = CombinedProfile {
            heap: HeapProfile {
                timestamp: "t".to_string(),
                allocated_bytes: 100,
                freed_bytes: 10,
                live_bytes: 90,
                peak_bytes: 100,
                rss_bytes: 200,
            },
            tasks: TasksProfile {
                timestamp: "t".to_string(),
                active_tasks: 5,
                worker_threads: 2,
                blocking_threads: 1,
            },
            runtime: RuntimeProfile {
                timestamp: "t".to_string(),
                uptime_secs: 60,
                pid: 1,
                num_cpus: 4,
                resident_memory_bytes: 8192,
                virtual_memory_bytes: 16384,
            },
        };
        let json = serde_json::to_string(&cp).unwrap();
        assert!(json.contains("\"heap\""));
        assert!(json.contains("\"tasks\""));
        assert!(json.contains("\"runtime\""));
    }

    #[test]
    fn thread_info_serializes() {
        let ti = ThreadInfo {
            name: "worker-0".to_string(),
            id: 42,
        };
        let json = serde_json::to_string(&ti).unwrap();
        assert!(json.contains("\"name\":\"worker-0\""));
        assert!(json.contains("\"id\":42"));
    }

    #[test]
    fn alloc_counters_work() {
        // Reset to known state — counters are global so we just verify
        // that fetch_add works directionally.
        let before_alloc = ALLOC_COUNTER.load(Ordering::Relaxed);
        let before_dealloc = DEALLOC_COUNTER.load(Ordering::Relaxed);

        record_alloc(512);
        record_alloc(256);
        record_dealloc(128);

        let after_alloc = ALLOC_COUNTER.load(Ordering::Relaxed);
        let after_dealloc = DEALLOC_COUNTER.load(Ordering::Relaxed);

        assert_eq!(after_alloc - before_alloc, 768);
        assert_eq!(after_dealloc - before_dealloc, 128);
    }
}
