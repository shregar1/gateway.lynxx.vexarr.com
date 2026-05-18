use crate::db::Repository;
use crate::error::GatewayError;
use crate::models::RateLimitSimulation;
use std::sync::Arc;
use uuid::Uuid;

pub struct RateLimitService {
    repo: Arc<dyn Repository>,
}

impl RateLimitService {
    pub fn new(repo: Arc<dyn Repository>) -> Self {
        Self { repo }
    }

    pub async fn list_simulations(
        &self,
        service_id: &Uuid,
    ) -> Result<Vec<RateLimitSimulation>, GatewayError> {
        self.repo.list_rate_limit_simulations(service_id).await
    }

    pub async fn create_simulation(&self, sim: &RateLimitSimulation) -> Result<(), GatewayError> {
        self.repo.create_rate_limit_simulation(sim).await
    }

    pub async fn get_simulation(
        &self,
        id: &Uuid,
    ) -> Result<Option<RateLimitSimulation>, GatewayError> {
        self.repo.get_rate_limit_simulation(id).await
    }
}

impl crate::abstractions::IService for RateLimitService {
    fn repo(&self) -> &Arc<dyn Repository> {
        &self.repo
    }
}
