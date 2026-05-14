use crate::db::Repository;
use crate::models::LogEntry;
use chrono::Utc;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use uuid::Uuid;

const BUFFER_CAP: usize = 200;
const FLUSH_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct LogWriter {
    tx: mpsc::Sender<LogEntry>,
}

impl LogWriter {
    pub fn new(repo: Arc<dyn Repository>, channel_size: usize) -> Self {
        let (tx, rx) = mpsc::channel(channel_size);
        tokio::spawn(flush_loop(rx, repo));
        Self { tx }
    }

    pub fn send(&self, entry: LogEntry) {
        let _ = self.tx.try_send(entry);
    }

    pub fn log(
        &self,
        method: &str,
        path: &str,
        client_ip: &str,
        service_id: Option<Uuid>,
        route_id: Option<Uuid>,
        project_id: Option<Uuid>,
        status: Option<u16>,
        duration_ms: i64,
        level: &str,
        message: &str,
    ) {
        let nil = Uuid::nil();
        let route_id_val = route_id.filter(|id| *id != nil);
        let now = Utc::now();
        self.send(LogEntry {
            id: Uuid::new_v4(),
            urn: Uuid::new_v4().to_string(),
            ts: now,
            level: level.to_string(),
            message: message.to_string(),
            service_id,
            route_id: route_id_val,
            project_id,
            method: Some(method.to_string()),
            path: Some(path.to_string()),
            status: status.map(|s| s as i32),
            duration_ms: Some(duration_ms),
            client_ip: if client_ip.is_empty() {
                None
            } else {
                Some(client_ip.to_string())
            },
            metadata: None,
            created_at: now,
            updated_at: now,
        });
    }
}

async fn flush_loop(mut rx: mpsc::Receiver<LogEntry>, repo: Arc<dyn Repository>) {
    let mut buffer = Vec::with_capacity(BUFFER_CAP);
    let mut interval = tokio::time::interval(FLUSH_INTERVAL);
    interval.tick().await;

    loop {
        tokio::select! {
            maybe = rx.recv() => {
                match maybe {
                    Some(entry) => {
                        buffer.push(entry);
                        if buffer.len() >= BUFFER_CAP {
                            flush(&repo, &mut buffer).await;
                        }
                    }
                    None => {
                        flush(&repo, &mut buffer).await;
                        break;
                    }
                }
            }
            _ = interval.tick() => {
                if !buffer.is_empty() {
                    flush(&repo, &mut buffer).await;
                }
            }
        }
    }
}

async fn flush(repo: &Arc<dyn Repository>, buffer: &mut Vec<LogEntry>) {
    if buffer.is_empty() {
        return;
    }
    if let Err(e) = repo.as_ref().insert_logs(buffer).await {
        tracing::warn!(count = buffer.len(), error = %e, "failed to flush request logs");
    }
    buffer.clear();
}

pub fn spawn_log_pruner(repo: Arc<dyn Repository>, retention_days: u32) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        interval.tick().await;
        loop {
            interval.tick().await;
            match repo.prune_logs(retention_days).await {
                Ok(n) if n > 0 => tracing::info!(deleted = n, "pruned old log entries"),
                Err(e) => tracing::warn!(error = %e, "log pruning failed"),
                _ => {}
            }
        }
    });
}
