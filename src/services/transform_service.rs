use crate::db::Repository;
use crate::error::GatewayError;
use crate::models::TransformRule;
use std::sync::Arc;
use uuid::Uuid;

pub struct TransformService {
    repo: Arc<dyn Repository>,
}

impl TransformService {
    pub fn new(repo: Arc<dyn Repository>) -> Self {
        Self { repo }
    }

    pub async fn list(&self, service_id: &Uuid) -> Result<Vec<TransformRule>, GatewayError> {
        self.repo.list_transform_rules(service_id).await
    }

    pub async fn get(&self, id: &Uuid) -> Result<Option<TransformRule>, GatewayError> {
        self.repo.get_transform_rule(id).await
    }

    pub async fn create(&self, rule: &TransformRule) -> Result<(), GatewayError> {
        self.repo.create_transform_rule(rule).await
    }

    pub async fn update(&self, id: &Uuid, rule: &TransformRule) -> Result<(), GatewayError> {
        self.repo.update_transform_rule(id, rule).await
    }

    pub async fn delete(&self, id: &Uuid) -> Result<bool, GatewayError> {
        self.repo.delete_transform_rule(id).await
    }
}

impl crate::abstractions::IService for TransformService {
    fn repo(&self) -> &Arc<dyn Repository> {
        &self.repo
    }
}
