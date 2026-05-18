use crate::db::Repository;
use crate::error::GatewayError;
use crate::models::ApiVersion;
use std::sync::Arc;
use uuid::Uuid;

pub struct VersionService {
    repo: Arc<dyn Repository>,
}

impl VersionService {
    pub fn new(repo: Arc<dyn Repository>) -> Self {
        Self { repo }
    }

    pub async fn list(&self, service_id: &Uuid) -> Result<Vec<ApiVersion>, GatewayError> {
        self.repo.list_api_versions(service_id).await
    }

    pub async fn get(&self, id: &Uuid) -> Result<Option<ApiVersion>, GatewayError> {
        self.repo.get_api_version(id).await
    }

    pub async fn create(&self, version: &ApiVersion) -> Result<(), GatewayError> {
        self.repo.create_api_version(version).await
    }

    pub async fn update(&self, id: &Uuid, version: &ApiVersion) -> Result<(), GatewayError> {
        self.repo.update_api_version(id, version).await
    }

    pub async fn delete(&self, id: &Uuid) -> Result<bool, GatewayError> {
        self.repo.delete_api_version(id).await
    }
}

impl crate::abstractions::IService for VersionService {
    fn repo(&self) -> &Arc<dyn Repository> {
        &self.repo
    }
}
