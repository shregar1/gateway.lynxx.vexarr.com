//! Abstraction layer for certificate storage.
//!
//! Multi-node gateway deployments need a shared store for:
//! - ACME certificates and account keys
//! - OCSP staple responses
//! - Session Ticket Encryption Keys (STEK)
//!
//! Three backends are provided:
//! - **File** (default) — reads/writes to local disk; suitable for single-node.
//! - **Redis** — uses the existing `redis` dependency; good for ephemeral
//!   shared state with optional TTL.
//! - **Postgres** — uses the existing `sqlx` dependency; durable storage for
//!   clusters that already share a Postgres database.
//!
//! The ACME manager does not consume this store yet; this module builds the
//! abstraction and backends so future work can swap in the configured store.

use crate::config::CertStoreConfig;
use crate::error::GatewayError;
use async_trait::async_trait;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Key-value store for certificate material.
///
/// Keys are opaque strings (e.g. `"acme/example.com/cert.pem"`). Values
/// are raw bytes. An optional TTL (seconds) lets backends auto-expire
/// entries — useful for OCSP staples and STEK rotation keys.
#[async_trait]
pub trait CertStore: Send + Sync {
    /// Retrieve a value by key. Returns `None` if the key doesn't exist or
    /// has expired.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, GatewayError>;

    /// Upsert a key-value pair. When `ttl_secs` is `Some`, the backend
    /// should auto-expire the entry after that many seconds. A `None`
    /// TTL means "persist indefinitely".
    async fn put(&self, key: &str, value: &[u8], ttl_secs: Option<u64>)
        -> Result<(), GatewayError>;

    /// Delete a key. No-op if the key doesn't exist.
    async fn delete(&self, key: &str) -> Result<(), GatewayError>;

    /// List all keys that start with `prefix`. Returns an empty vec when
    /// no keys match.
    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, GatewayError>;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Build a [`CertStore`] from the gateway config. The `database_url` is
/// passed through so the Postgres backend can reuse the gateway's pool
/// when `cert_store.backend = "postgres"`.
pub async fn from_config(
    cfg: &CertStoreConfig,
    database_url: &str,
) -> Result<Arc<dyn CertStore>, GatewayError> {
    match cfg.backend.as_str() {
        "file" => {
            let dir = if cfg.file_dir.is_empty() {
                default_file_dir()
            } else {
                cfg.file_dir.clone()
            };
            Ok(Arc::new(FileCertStore::new(dir)))
        }
        "redis" => {
            if cfg.redis_url.is_empty() {
                return Err(GatewayError::Internal(
                    "cert_store.backend = \"redis\" requires cert_store.redis_url".into(),
                ));
            }
            let store = RedisCertStore::connect(&cfg.redis_url).await?;
            Ok(Arc::new(store))
        }
        "postgres" => {
            let store = PostgresCertStore::connect(database_url).await?;
            Ok(Arc::new(store))
        }
        other => Err(GatewayError::Internal(format!(
            "cert_store.backend: unknown backend \"{other}\" (accepted: file, redis, postgres)"
        ))),
    }
}

fn default_file_dir() -> String {
    dirs::home_dir()
        .map(|h| {
            h.join(".lynxx")
                .join("certs")
                .to_string_lossy()
                .into_owned()
        })
        .unwrap_or_else(|| "/var/lib/lynxx/certs".to_string())
}

// ---------------------------------------------------------------------------
// File backend
// ---------------------------------------------------------------------------

/// Stores cert material as plain files under a base directory. Keys are
/// treated as relative paths: `"acme/example.com/cert.pem"` maps to
/// `{base_dir}/acme/example.com/cert.pem`. TTL is ignored (files persist
/// until explicitly deleted).
pub struct FileCertStore {
    base_dir: String,
}

impl FileCertStore {
    pub fn new(base_dir: String) -> Self {
        Self { base_dir }
    }

    fn full_path(&self, key: &str) -> std::path::PathBuf {
        std::path::Path::new(&self.base_dir).join(key)
    }
}

#[async_trait]
impl CertStore for FileCertStore {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, GatewayError> {
        let path = self.full_path(key);
        match tokio::fs::read(&path).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(GatewayError::Internal(format!(
                "cert_store file read {}: {e}",
                path.display()
            ))),
        }
    }

    async fn put(
        &self,
        key: &str,
        value: &[u8],
        _ttl_secs: Option<u64>,
    ) -> Result<(), GatewayError> {
        let path = self.full_path(key);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                GatewayError::Internal(format!("cert_store file mkdir {}: {e}", parent.display()))
            })?;
        }
        tokio::fs::write(&path, value).await.map_err(|e| {
            GatewayError::Internal(format!("cert_store file write {}: {e}", path.display()))
        })
    }

    async fn delete(&self, key: &str) -> Result<(), GatewayError> {
        let path = self.full_path(key);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(GatewayError::Internal(format!(
                "cert_store file delete {}: {e}",
                path.display()
            ))),
        }
    }

    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, GatewayError> {
        let search_dir = self.full_path(prefix);
        // If the prefix resolves to a directory, list its contents
        // recursively. If it doesn't exist, return empty.
        let dir = if search_dir.is_dir() {
            search_dir
        } else if let Some(parent) = search_dir.parent() {
            if parent.is_dir() {
                parent.to_path_buf()
            } else {
                return Ok(Vec::new());
            }
        } else {
            return Ok(Vec::new());
        };

        let mut keys = Vec::new();
        let mut stack = vec![dir];
        let base = std::path::Path::new(&self.base_dir);

        while let Some(current) = stack.pop() {
            let mut entries = match tokio::fs::read_dir(&current).await {
                Ok(e) => e,
                Err(_) => continue,
            };
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(rel) = path.strip_prefix(base) {
                    let key = rel.to_string_lossy().to_string();
                    if key.starts_with(prefix) {
                        keys.push(key);
                    }
                }
            }
        }
        keys.sort();
        Ok(keys)
    }
}

// ---------------------------------------------------------------------------
// Redis backend
// ---------------------------------------------------------------------------

/// Certificate store backed by Redis. Keys are prefixed with `lynxx:certs:`
/// to avoid collisions with other gateway data. TTL is natively supported
/// via `SET EX`.
pub struct RedisCertStore {
    conn: redis::aio::ConnectionManager,
}

impl RedisCertStore {
    const PREFIX: &'static str = "lynxx:certs:";

    pub async fn connect(url: &str) -> Result<Self, GatewayError> {
        let client = redis::Client::open(url)
            .map_err(|e| GatewayError::Internal(format!("cert_store redis open: {e}")))?;
        let conn = redis::aio::ConnectionManager::new(client)
            .await
            .map_err(|e| GatewayError::Internal(format!("cert_store redis connect: {e}")))?;
        Ok(Self { conn })
    }

    fn prefixed(key: &str) -> String {
        format!("{}{}", Self::PREFIX, key)
    }
}

#[async_trait]
impl CertStore for RedisCertStore {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, GatewayError> {
        use redis::AsyncCommands;
        let mut conn = self.conn.clone();
        let result: Option<Vec<u8>> = conn
            .get(Self::prefixed(key))
            .await
            .map_err(|e| GatewayError::Internal(format!("cert_store redis GET: {e}")))?;
        Ok(result)
    }

    async fn put(
        &self,
        key: &str,
        value: &[u8],
        ttl_secs: Option<u64>,
    ) -> Result<(), GatewayError> {
        use redis::AsyncCommands;
        let mut conn = self.conn.clone();
        let k = Self::prefixed(key);
        if let Some(ttl) = ttl_secs {
            conn.set_ex::<_, _, ()>(&k, value, ttl)
                .await
                .map_err(|e| GatewayError::Internal(format!("cert_store redis SET EX: {e}")))?;
        } else {
            conn.set::<_, _, ()>(&k, value)
                .await
                .map_err(|e| GatewayError::Internal(format!("cert_store redis SET: {e}")))?;
        }
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), GatewayError> {
        use redis::AsyncCommands;
        let mut conn = self.conn.clone();
        conn.del::<_, ()>(Self::prefixed(key))
            .await
            .map_err(|e| GatewayError::Internal(format!("cert_store redis DEL: {e}")))?;
        Ok(())
    }

    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, GatewayError> {
        use redis::AsyncCommands;
        let mut conn = self.conn.clone();
        let pattern = format!("{}{}*", Self::PREFIX, prefix);
        let raw_keys: Vec<String> = conn
            .keys(pattern)
            .await
            .map_err(|e| GatewayError::Internal(format!("cert_store redis KEYS: {e}")))?;
        let prefix_len = Self::PREFIX.len();
        let keys = raw_keys
            .into_iter()
            .filter_map(|k| {
                if k.len() > prefix_len {
                    Some(k[prefix_len..].to_string())
                } else {
                    None
                }
            })
            .collect();
        Ok(keys)
    }
}

// ---------------------------------------------------------------------------
// Postgres backend
// ---------------------------------------------------------------------------

/// Certificate store backed by Postgres. Uses a `cert_store` table with
/// columns `(key TEXT PK, value BYTEA, expires_at TIMESTAMPTZ NULL)`.
/// Expired rows are lazily pruned on read; a periodic reaper is not
/// included in v1.
pub struct PostgresCertStore {
    pool: sqlx::PgPool,
}

impl PostgresCertStore {
    pub async fn connect(database_url: &str) -> Result<Self, GatewayError> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(database_url)
            .await
            .map_err(|e| GatewayError::Internal(format!("cert_store postgres connect: {e}")))?;

        // Auto-create the table on first connect.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS cert_store (
                key         TEXT PRIMARY KEY,
                value       BYTEA NOT NULL,
                expires_at  TIMESTAMPTZ
            )",
        )
        .execute(&pool)
        .await
        .map_err(|e| GatewayError::Internal(format!("cert_store postgres migrate: {e}")))?;

        Ok(Self { pool })
    }
}

#[async_trait]
impl CertStore for PostgresCertStore {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, GatewayError> {
        let row: Option<(Vec<u8>,)> = sqlx::query_as(
            "SELECT value FROM cert_store \
             WHERE key = $1 \
             AND (expires_at IS NULL OR expires_at > NOW())",
        )
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| GatewayError::Internal(format!("cert_store postgres SELECT: {e}")))?;
        Ok(row.map(|(v,)| v))
    }

    async fn put(
        &self,
        key: &str,
        value: &[u8],
        ttl_secs: Option<u64>,
    ) -> Result<(), GatewayError> {
        let expires = ttl_secs.map(|t| chrono::Utc::now() + chrono::Duration::seconds(t as i64));
        sqlx::query(
            "INSERT INTO cert_store (key, value, expires_at) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (key) DO UPDATE SET value = $2, expires_at = $3",
        )
        .bind(key)
        .bind(value)
        .bind(expires)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| GatewayError::Internal(format!("cert_store postgres UPSERT: {e}")))?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), GatewayError> {
        sqlx::query("DELETE FROM cert_store WHERE key = $1")
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(|e| GatewayError::Internal(format!("cert_store postgres DELETE: {e}")))?;
        Ok(())
    }

    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, GatewayError> {
        let pattern = format!("{prefix}%");
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT key FROM cert_store \
             WHERE key LIKE $1 \
             AND (expires_at IS NULL OR expires_at > NOW()) \
             ORDER BY key",
        )
        .bind(&pattern)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| GatewayError::Internal(format!("cert_store postgres list: {e}")))?;
        Ok(rows.into_iter().map(|(k,)| k).collect())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// File backend: round-trip get/put/delete/list.
    #[tokio::test]
    async fn file_backend_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileCertStore::new(tmp.path().to_string_lossy().into_owned());

        // get non-existent key
        assert!(store.get("missing").await.unwrap().is_none());

        // put + get
        store
            .put("acme/example.com/cert.pem", b"CERT", None)
            .await
            .unwrap();
        let val = store
            .get("acme/example.com/cert.pem")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(val, b"CERT");

        // overwrite
        store
            .put("acme/example.com/cert.pem", b"CERT2", None)
            .await
            .unwrap();
        let val = store
            .get("acme/example.com/cert.pem")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(val, b"CERT2");

        // second key
        store
            .put("acme/example.com/key.pem", b"KEY", None)
            .await
            .unwrap();

        // list by prefix
        let keys = store.list_keys("acme/example.com/").await.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"acme/example.com/cert.pem".to_string()));
        assert!(keys.contains(&"acme/example.com/key.pem".to_string()));

        // delete
        store.delete("acme/example.com/cert.pem").await.unwrap();
        assert!(store
            .get("acme/example.com/cert.pem")
            .await
            .unwrap()
            .is_none());

        // delete non-existent is fine
        store.delete("nope").await.unwrap();

        // list after delete
        let keys = store.list_keys("acme/example.com/").await.unwrap();
        assert_eq!(keys.len(), 1);
    }

    /// File backend: empty prefix list on non-existent dir returns empty.
    #[tokio::test]
    async fn file_backend_list_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileCertStore::new(tmp.path().join("nope").to_string_lossy().into_owned());
        let keys = store.list_keys("whatever").await.unwrap();
        assert!(keys.is_empty());
    }

    /// Verify the factory rejects unknown backends.
    #[tokio::test]
    async fn factory_unknown_backend() {
        let cfg = CertStoreConfig {
            backend: "dynamodb".into(),
            redis_url: String::new(),
            file_dir: String::new(),
        };
        match from_config(&cfg, "").await {
            Err(e) => assert!(e.to_string().contains("dynamodb")),
            Ok(_) => panic!("expected error for unknown backend"),
        }
    }

    /// Verify the factory rejects redis without a URL.
    #[tokio::test]
    async fn factory_redis_no_url() {
        let cfg = CertStoreConfig {
            backend: "redis".into(),
            redis_url: String::new(),
            file_dir: String::new(),
        };
        match from_config(&cfg, "").await {
            Err(e) => assert!(e.to_string().contains("redis_url")),
            Ok(_) => panic!("expected error for redis without URL"),
        }
    }

    /// Verify the factory creates a file store with custom dir.
    #[tokio::test]
    async fn factory_file_backend() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = CertStoreConfig {
            backend: "file".into(),
            redis_url: String::new(),
            file_dir: tmp.path().to_string_lossy().into_owned(),
        };
        let store = from_config(&cfg, "").await.unwrap();
        store.put("test/key", b"val", None).await.unwrap();
        let v = store.get("test/key").await.unwrap().unwrap();
        assert_eq!(v, b"val");
    }
}
