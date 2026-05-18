use crate::db::Repository;
use crate::error::GatewayError;
use crate::models::LoadTest;
use std::sync::Arc;
use uuid::Uuid;

pub struct LoadTestService {
    repo: Arc<dyn Repository>,
}

impl LoadTestService {
    pub fn new(repo: Arc<dyn Repository>) -> Self {
        Self { repo }
    }

    pub async fn list(&self, service_id: &Uuid) -> Result<Vec<LoadTest>, GatewayError> {
        self.repo.list_load_tests(service_id).await
    }

    pub async fn get(&self, id: &Uuid) -> Result<Option<LoadTest>, GatewayError> {
        self.repo.get_load_test(id).await
    }

    pub async fn create(&self, test: &LoadTest) -> Result<(), GatewayError> {
        self.repo.create_load_test(test).await
    }

    pub async fn update(&self, id: &Uuid, test: &LoadTest) -> Result<(), GatewayError> {
        self.repo.update_load_test(id, test).await
    }

    pub async fn delete(&self, id: &Uuid) -> Result<bool, GatewayError> {
        self.repo.delete_load_test(id).await
    }
}

impl crate::abstractions::IService for LoadTestService {
    fn repo(&self) -> &Arc<dyn Repository> {
        &self.repo
    }
}
