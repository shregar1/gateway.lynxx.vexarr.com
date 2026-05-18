//! WASM module file watcher.
//!
//! Polls the filesystem for mtime changes on registered `.wasm` module
//! paths. When a change is detected the watcher signals the
//! `PluginExecutor` to rebuild, which recompiles the module from disk
//! without requiring a gateway restart.
//!
//! Design choices:
//!
//! - **Polling over inotify** — keeps the dependency tree minimal and
//!   works identically on Linux, macOS, and Windows. A 2-second poll
//!   interval is cheap (one `stat()` per path) and perfectly adequate
//!   for a deploy-time reload trigger.
//! - **Tolerates missing files** — during a rolling deploy the old
//!   binary is often unlinked before the new one lands. The watcher
//!   silently skips missing paths and picks them back up on the next
//!   poll once the file reappears.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::Mutex;

/// Poll interval for filesystem mtime checks.
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

pub struct WasmWatcher {
    paths: Arc<Mutex<HashMap<PathBuf, SystemTime>>>,
}

impl Default for WasmWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmWatcher {
    pub fn new() -> Self {
        Self {
            paths: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a module path for watching. Captures the current mtime as
    /// the baseline; only future changes will fire the callback.
    pub async fn register(&self, path: PathBuf) {
        let mtime = current_mtime(&path).await;
        let mut paths = self.paths.lock().await;
        if let Some(t) = mtime {
            paths.insert(path, t);
        } else {
            // File doesn't exist yet (e.g. deploy in progress). Record it
            // with epoch so we fire on first appearance.
            paths.insert(path, SystemTime::UNIX_EPOCH);
        }
    }

    /// Replace the entire set of watched paths. Paths that were already
    /// tracked keep their recorded mtime; new paths snapshot the current
    /// mtime; removed paths are dropped.
    pub async fn sync_paths(&self, new_paths: Vec<PathBuf>) {
        let mut guard = self.paths.lock().await;
        let mut next: HashMap<PathBuf, SystemTime> = HashMap::with_capacity(new_paths.len());
        for p in new_paths {
            if let Some(existing) = guard.get(&p) {
                next.insert(p, *existing);
            } else {
                let mtime = current_mtime(&p).await.unwrap_or(SystemTime::UNIX_EPOCH);
                next.insert(p, mtime);
            }
        }
        *guard = next;
    }

    /// Spawn the polling loop. Returns a `JoinHandle` for the background
    /// task. `on_change` is invoked with the path that changed; multiple
    /// paths changing in the same poll cycle each trigger a separate call.
    pub fn spawn<F>(&self, on_change: F) -> tokio::task::JoinHandle<()>
    where
        F: Fn(PathBuf) + Send + Sync + 'static,
    {
        let paths = self.paths.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(POLL_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                let guard = paths.lock().await;
                let snapshot: Vec<(PathBuf, SystemTime)> =
                    guard.iter().map(|(p, t)| (p.clone(), *t)).collect();
                // Release the lock while doing I/O so register() isn't blocked.
                drop(guard);

                if snapshot.is_empty() {
                    continue;
                }

                for (path, old_mtime) in &snapshot {
                    let new_mtime = match current_mtime(path).await {
                        Some(t) => t,
                        None => continue, // file missing, tolerate
                    };
                    if new_mtime != *old_mtime {
                        tracing::info!(
                            path = %path.display(),
                            "wasm module changed, triggering reload"
                        );
                        // Update the stored mtime before firing the callback
                        // so we don't re-fire on the same change.
                        let mut guard = paths.lock().await;
                        if let Some(entry) = guard.get_mut(path) {
                            *entry = new_mtime;
                        }
                        drop(guard);
                        on_change(path.clone());
                    }
                }
            }
        })
    }
}

/// Read a file's mtime via `tokio::fs::metadata`. Returns `None` when the
/// file does not exist or the metadata call fails (permissions, dangling
/// symlink, etc.).
async fn current_mtime(path: &PathBuf) -> Option<SystemTime> {
    tokio::fs::metadata(path)
        .await
        .ok()
        .and_then(|m| m.modified().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use tokio::sync::Notify;

    #[tokio::test]
    async fn register_captures_initial_mtime() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "hello").unwrap();
        let path = tmp.path().to_path_buf();

        let w = WasmWatcher::new();
        w.register(path.clone()).await;

        let guard = w.paths.lock().await;
        assert!(guard.contains_key(&path));
        assert_ne!(guard[&path], SystemTime::UNIX_EPOCH);
    }

    #[tokio::test]
    async fn register_missing_file_uses_epoch() {
        let path = PathBuf::from("/tmp/does-not-exist-lynxx-test.wasm");
        let w = WasmWatcher::new();
        w.register(path.clone()).await;

        let guard = w.paths.lock().await;
        assert_eq!(guard[&path], SystemTime::UNIX_EPOCH);
    }

    #[tokio::test]
    async fn sync_paths_drops_removed_and_adds_new() {
        let w = WasmWatcher::new();
        let a = PathBuf::from("/tmp/a.wasm");
        let b = PathBuf::from("/tmp/b.wasm");
        let c = PathBuf::from("/tmp/c.wasm");
        w.register(a.clone()).await;
        w.register(b.clone()).await;

        // sync to [b, c] — a should be dropped, c added
        w.sync_paths(vec![b.clone(), c.clone()]).await;

        let guard = w.paths.lock().await;
        assert!(!guard.contains_key(&a));
        assert!(guard.contains_key(&b));
        assert!(guard.contains_key(&c));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn detects_mtime_change() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "v1").unwrap();
        let path = tmp.path().to_path_buf();

        let w = WasmWatcher::new();
        w.register(path.clone()).await;

        let changed = Arc::new(Notify::new());
        let changed2 = changed.clone();
        let _handle = w.spawn(move |_p| {
            changed2.notify_one();
        });

        // Give the first tick time to run (no change yet).
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Mutate the file.
        writeln!(tmp, "v2").unwrap();
        tmp.flush().unwrap();

        // Wait for the callback to fire (poll interval is 2s, add margin).
        tokio::time::timeout(std::time::Duration::from_secs(5), changed.notified())
            .await
            .expect("watcher should detect the mtime change within 5 seconds");
    }
}
