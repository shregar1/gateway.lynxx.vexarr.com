use crate::db::Repository;
use crate::error::GatewayError;
use crate::models::Target;
use std::sync::Arc;
use uuid::Uuid;

pub struct TargetService {
    repo: Arc<dyn Repository>,
}

impl TargetService {
    pub fn new(repo: Arc<dyn Repository>) -> Self {
        Self { repo }
    }

    pub async fn list(&self) -> Result<Vec<Target>, GatewayError> {
        self.repo.list_targets().await
    }

    pub async fn get(&self, id: &Uuid) -> Result<Option<Target>, GatewayError> {
        self.repo.get_target(id).await
    }

    pub async fn get_for_service(&self, service_id: &Uuid) -> Result<Vec<Target>, GatewayError> {
        self.repo.list_targets_for_service(service_id).await
    }

    pub async fn create(&self, target: &Target) -> Result<(), GatewayError> {
        self.repo.create_target(target).await
    }

    pub async fn update(&self, id: &Uuid, target: &Target) -> Result<(), GatewayError> {
        self.repo.update_target(id, target).await
    }

    pub async fn delete(&self, id: &Uuid) -> Result<bool, GatewayError> {
        self.repo.delete_target(id).await
    }
}

impl crate::abstractions::IService for TargetService {
    fn repo(&self) -> &Arc<dyn Repository> {
        &self.repo
    }
}
