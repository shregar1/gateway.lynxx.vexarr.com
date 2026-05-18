use crate::db::Repository;
use crate::error::GatewayError;
use crate::models::{CacheEntry, CacheStats};
use std::sync::Arc;
use uuid::Uuid;

pub struct CacheService {
    repo: Arc<dyn Repository>,
}

impl CacheService {
    pub fn new(repo: Arc<dyn Repository>) -> Self {
        Self { repo }
    }

    pub async fn list_entries(&self, service_id: &Uuid) -> Result<Vec<CacheEntry>, GatewayError> {
        self.repo.list_cache_entries(service_id).await
    }

    pub async fn get_entry(&self, id: &Uuid) -> Result<Option<CacheEntry>, GatewayError> {
        self.repo.get_cache_entry(id).await
    }

    pub async fn upsert_entry(&self, entry: &CacheEntry) -> Result<(), GatewayError> {
        self.repo.upsert_cache_entry(entry).await
    }

    pub async fn delete_entry(&self, id: &Uuid) -> Result<bool, GatewayError> {
        self.repo.delete_cache_entry(id).await
    }

    pub async fn purge(&self, service_id: &Uuid) -> Result<u64, GatewayError> {
        self.repo.purge_cache(service_id).await
    }

    pub async fn stats(&self, service_id: &Uuid) -> Result<CacheStats, GatewayError> {
        self.repo.cache_stats(service_id).await
    }
}

impl crate::abstractions::IService for CacheService {
    fn repo(&self) -> &Arc<dyn Repository> {
        &self.repo
    }
}
